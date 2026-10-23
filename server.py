#!/usr/bin/env python3
"""roxy-accounts — 自管理账号系统 (Roxy 浏览器自动化)
阶段1: 代理池 — socks5 静态代理自管理, 无下层同步。
导入/导出/测活/备注/封禁标记; bound[] 预留账号绑定。"""
import base64
import datetime
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import zipfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = 8322
BJ_TZ = datetime.timezone(datetime.timedelta(hours=8))  # 北京时间 (无夏令时)

# ---------------- 代理池存储 ----------------
PROXIES_FILE = os.path.join(BASE_DIR, "proxies.json")
_px_lock = threading.Lock()


def _load_proxies():
    try:
        return json.load(open(PROXIES_FILE)).get("proxies") or []
    except Exception:
        return []


def _save_proxies(px):
    with _px_lock:
        tmp = PROXIES_FILE + ".tmp"
        json.dump({"proxies": px}, open(tmp, "w"),
                  ensure_ascii=False, indent=1)
        os.replace(tmp, PROXIES_FILE)


# ---- Google 侧独立代理池: gproxies.json ----
GPROXIES_FILE = os.path.join(BASE_DIR, "gproxies.json")
_gpx_lock = threading.Lock()


def _load_gproxies():
    """独立 G 代理池。首次访问不存在时用 proxies.json 播种:
    条目原样复制 (同 id —— 存量 gaccount.proxy_id 不失联),
    bound 只保留 gaccounts 里 proxy_id 指向自己的邮箱,
    GPT 的绑定/冷却不带过来。"""
    if not os.path.exists(GPROXIES_FILE):
        try:
            src = json.load(open(PROXIES_FILE)).get("proxies") or []
        except Exception:
            src = []
        gbound = {}
        try:
            for a in (json.load(open(GACCOUNTS_FILE))
                      .get("accounts") or []):
                if a.get("proxy_id"):
                    gbound.setdefault(a["proxy_id"], []) \
                        .append(a["email"])
        except Exception:
            pass
        px = []
        for p in src:
            q = dict(p)
            q["bound"] = list(gbound.get(p["id"]) or [])
            q.pop("cool_email", None)
            q.pop("cool_until", None)
            px.append(q)
        _save_gproxies(px)
        return px
    try:
        return json.load(open(GPROXIES_FILE)).get("proxies") or []
    except Exception:
        return []


def _save_gproxies(px):
    with _gpx_lock:
        tmp = GPROXIES_FILE + ".tmp"
        json.dump({"proxies": px}, open(tmp, "w"),
                  ensure_ascii=False, indent=1)
        os.replace(tmp, GPROXIES_FILE)


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _new_proxy(scheme, host, port, username, password):
    return {
        "id": "px_" + uuid.uuid4().hex[:10],
        "scheme": scheme, "host": host, "port": port,
        "username": username, "password": password,
        "note": "", "banned": False, "ban_reason": [],
        "bound": [],                      # 预留: 绑定的账号邮箱
        "alive": None, "latency_ms": None, "exit_ip": None,
        "checked_at": None, "last_used": None,
        "created_at": _now(),
    }


# ---------------- 导入解析 ----------------
def _parse_proxy_line(line, default_scheme="socks5"):
    """一行 -> (dict|None, err|None)。支持:
    scheme://user:pass@host:port | user:pass@host:port |
    host:port:user:pass (pass 可含冒号) | host:port"""
    s = line.strip()
    if not s:
        return None, "empty"
    if s.startswith("#"):
        return None, "comment"
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9]*)://(.+)$", s)
    if m:
        scheme, rest = m.group(1).lower(), m.group(2)
        if "@" in rest:
            auth, hp = rest.rsplit("@", 1)
            user, pwd = (auth.split(":", 1) + [""])[:2] \
                if ":" in auth else (auth, "")
        else:
            user, pwd, hp = "", "", rest
        if ":" not in hp:
            return None, "缺端口"
        host, port = hp.rsplit(":", 1)
    elif "@" in s:
        scheme = default_scheme
        auth, hp = s.rsplit("@", 1)
        user, pwd = (auth.split(":", 1) + [""])[:2] \
            if ":" in auth else (auth, "")
        if ":" not in hp:
            return None, "缺端口"
        host, port = hp.rsplit(":", 1)
    else:
        scheme = default_scheme
        parts = s.split(":")
        if len(parts) == 2:
            host, port, user, pwd = parts[0], parts[1], "", ""
        elif len(parts) >= 4:
            host, port, user = parts[0], parts[1], parts[2]
            pwd = ":".join(parts[3:])          # 密码允许含冒号
        else:
            return None, "字段不足 (需 host:port[:user:pass])"
    host = host.strip()
    if not host:
        return None, "host 为空"
    try:
        port = int(str(port).strip())
        if not (0 < port < 65536):
            raise ValueError
    except Exception:
        return None, f"端口无效: {port}"
    if scheme == "socks5h":
        scheme = "socks5"
    if scheme not in ("socks5", "http", "https"):
        return None, f"未知协议: {scheme}"
    return {"scheme": scheme, "host": host, "port": port,
            "username": urllib.parse.unquote(user.strip()),
            "password": urllib.parse.unquote(pwd.strip())}, None


def _proxy_key(p):
    return (p["host"].lower(), int(p["port"]),
            (p.get("username") or "").lower())


def _proxy_url(p, fmt="colon"):
    """导出格式: colon=host:port:user:pass | url=socks5://u:p@h:p"""
    u, w = p.get("username") or "", p.get("password") or ""
    if fmt == "url":
        auth = f"{urllib.parse.quote(u)}:{urllib.parse.quote(w)}@" \
            if u else ""
        return f"{p['scheme']}://{auth}{p['host']}:{p['port']}"
    return f"{p['host']}:{p['port']}:{u}:{w}".rstrip(":")


# ---------------- SOCKS5 测活 ----------------
def _recv_n(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _s5_auth(s, username, password):
    """已连接的 socket 上做 socks5 问候+认证。返回 err|None。"""
    s.sendall(b"\x05\x02\x00\x02" if username else b"\x05\x01\x00")
    r = _recv_n(s, 2)
    if len(r) < 2 or r[0] != 5:
        return "握手无响应"
    if r[1] == 0xFF:
        return "代理拒绝所有认证方式"
    if r[1] == 0x02:
        u = (username or "").encode()
        w = (password or "").encode()
        if len(u) > 255 or len(w) > 255:
            return "账密过长"
        s.sendall(b"\x01" + bytes([len(u)]) + u
                  + bytes([len(w)]) + w)
        r = _recv_n(s, 2)
        if len(r) < 2 or r[1] != 0:
            return "用户名密码认证被拒"
    elif r[1] != 0x00:
        return f"代理要求未知认证 0x{r[1]:02x}"
    return None


def _s5_connect(s, host, port):
    """已认证 socks5 会话上发 CONNECT host:port。返回 err|None。"""
    try:
        req = b"\x05\x01\x00\x01" + socket.inet_aton(host) \
            + int(port).to_bytes(2, "big")
    except OSError:
        hb = host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb \
            + int(port).to_bytes(2, "big")
    s.sendall(req)
    r = _recv_n(s, 4)
    if len(r) < 4:
        return "CONNECT 无响应"
    if r[1] != 0:
        return f"CONNECT 被拒 code={r[1]}"
    atyp = r[3]
    if atyp == 1:
        _recv_n(s, 6)
    elif atyp == 3:
        ln = _recv_n(s, 1)
        _recv_n(s, (ln[0] if ln else 0) + 2)
    elif atyp == 4:
        _recv_n(s, 18)
    return None


def _proxy_tunnel(up, host, port, timeout, sock=None):
    """在 sock (None=直连 up 新建) 上跑 up 的代理协议隧道到
    host:port, 返回已就绪 socket。up = _parse_proxy_line dict。"""
    s = sock or socket.create_connection((up["host"],
                                          int(up["port"])),
                                         timeout=timeout)
    s.settimeout(timeout)
    label = up.get("_label") or "代理"
    if up["scheme"] == "socks5":
        e = _s5_auth(s, up.get("username"), up.get("password")) \
            or _s5_connect(s, host, port)
        if e:
            s.close()
            raise OSError(label + ": " + e)
        return s
    # http/https -> CONNECT 隧道
    cred = ""
    if up.get("username"):
        tok = base64.b64encode(
            f"{up['username']}:{up.get('password') or ''}"
            .encode()).decode()
        cred = f"Proxy-Authorization: Basic {tok}\r\n"
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\n"
              f"Host: {host}:{port}\r\n{cred}\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 8192:
        ch = s.recv(4096)
        if not ch:
            break
        buf += ch
    st = buf.split(b"\r\n", 1)[0]
    if b" 200" not in st:
        s.close()
        raise OSError(label + ": "
                      + st.decode(errors="ignore")[:60])
    return s


def _dial_via_upstream(up, host, port, timeout):
    """经上级代理隧道到 host:port, 返回已就绪 socket。"""
    up = dict(up)
    up["_label"] = "上级代理"
    return _proxy_tunnel(up, host, port, timeout)


_UNSET = object()


def _dial_via_account_proxy(p, host, port, timeout, up=_UNSET):
    """本机 → (上级代理 →) 账号代理 → host:port。
    账号代理只有经上级链式才握手得通 (RST 直连)。
    up 缺省走 GPT 设置; G 侧调用显式传 _gupstream()。"""
    if up is _UNSET:
        up = _upstream()
    if not up:
        q = dict(p)
        q["_label"] = "账号代理"
        return _proxy_tunnel(q, host, port, timeout)
    s = _proxy_tunnel(up, p["host"], int(p["port"]), timeout)
    q = dict(p)
    q["_label"] = "账号代理"
    return _proxy_tunnel(q, host, port, timeout, sock=s)


def _socks5_check(p, timeout=8, target=("api.ipify.org", 80),
                  upstream=None):
    """SOCKS5 握手 -> 认证 -> CONNECT target 取出口IP。
    upstream=_parse_proxy_line 的上级代理 dict 时先过它隧道。
    返回 (ok, latency_ms, exit_ip, err)。"""
    t0 = time.time()
    s = None
    err = None
    try:
        if upstream:
            s = _dial_via_upstream(upstream, p["host"],
                                   int(p["port"]), timeout)
        else:
            s = socket.create_connection(
                (p["host"], int(p["port"])), timeout=timeout)
            s.settimeout(timeout)
        err = _s5_auth(s, p.get("username"), p.get("password"))
        if not err:
            err = _s5_connect(s, target[0], target[1])
        if not err:
            s.sendall(b"GET / HTTP/1.0\r\nHost: "
                      + target[0].encode() + b"\r\n\r\n")
            data = b""
            while len(data) < 4096:
                chunk = s.recv(2048)
                if not chunk:
                    break
                data += chunk
            body = data.split(b"\r\n\r\n", 1)[-1].strip()
            ip = body.decode(errors="ignore")[:45] \
                if re.fullmatch(rb"[0-9a-fA-F.:]+", body or b"") else ""
            return True, int((time.time() - t0) * 1000), \
                ip or None, None
    except Exception as e:
        err = str(e)[:80]
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass
    return False, int((time.time() - t0) * 1000), None, err


# ---------------- 设置 ----------------
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.json")


def _settings():
    try:
        return json.load(open(SETTINGS_FILE))
    except Exception:
        return {}


def _save_settings(s):
    json.dump(s, open(SETTINGS_FILE, "w"), ensure_ascii=False, indent=1)


# ---------------- 空间母号 ----------------
MOTHERS_FILE = os.path.join(BASE_DIR, "mothers.json")


def _load_mothers():
    try:
        return json.load(open(MOTHERS_FILE)).get("mothers") or []
    except Exception:
        return []


def _save_mothers(ms):
    json.dump({"mothers": ms}, open(MOTHERS_FILE, "w"),
              ensure_ascii=False, indent=1)


def _space_mothers():
    """空间母号列表 —— 排除设置里的 Pat测试母号
    (Pat测试母号独属 PAT 检验, 不参与别的功能)。"""
    pat = (_settings().get("mother_window") or "").strip()
    return [m for m in _load_mothers() if m["name"] != pat]


def _upstream_of(s):
    """settings dict -> 上级代理 dict | None"""
    raw = (s.get("upstream_proxy") or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw          # 裸 host:port 默认 http
    d, _ = _parse_proxy_line(raw, "http")
    return d


def _upstream():
    return _upstream_of(_settings())


# ---- Google 侧独立设置: gsettings.json ----
GSETTINGS_FILE = os.path.join(BASE_DIR, "gsettings.json")


def _gsettings():
    """独立 G 设置。不存在时用 settings.json 播种。"""
    if not os.path.exists(GSETTINGS_FILE):
        try:
            s = json.load(open(SETTINGS_FILE))
        except Exception:
            s = {}
        _save_gsettings(s)
        return dict(s)
    try:
        return json.load(open(GSETTINGS_FILE))
    except Exception:
        return {}


def _save_gsettings(s):
    json.dump(s, open(GSETTINGS_FILE, "w"),
              ensure_ascii=False, indent=1)


def _gupstream():
    return _upstream_of(_gsettings())


def _gcool_secs():
    try:
        return int(float(
            _gsettings().get("proxy_cool_min") or 20) * 60)
    except Exception:
        return 1200


def _goauth_ttl_s():
    try:
        return max(60, int(float(
            _gsettings().get("oauth_ttl_min") or 10) * 60))
    except Exception:
        return 600


# ---------------- Roxy 配置 ----------------
ROXY_FILE = os.path.join(BASE_DIR, "roxy.json")
ROXY_DEFAULTS = {"host": "http://127.0.0.1:50000",
                 "api_key": "", "workspace_id": "",
                 "os": "macOS", "os_version": "15.3.2"}


def _roxy_cfg():
    cfg = dict(ROXY_DEFAULTS)
    try:
        cfg.update(json.load(open(ROXY_FILE)))
    except Exception:
        pass
    return cfg


def _roxy_call(path, body=None, timeout=30):
    cfg = _roxy_cfg()
    req = urllib.request.Request(cfg["host"].rstrip("/") + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"token": cfg["api_key"],
                 "content-type": "application/json"},
        method="POST" if body is not None else "GET")
    try:
        d = json.loads(urllib.request.urlopen(req, timeout=timeout).read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read()[:200]}"}
    except Exception as e:
        return {"error": str(e)}
    if d.get("code") not in (0, None):
        return {"error": d.get("msg") or str(d)[:200]}
    return d


def _roxy_proxyinfo(p):
    """本地代理 dict -> Roxy proxyInfo"""
    proto = (p.get("scheme") or "socks5").upper()
    if proto == "SOCKS5H":
        proto = "SOCKS5"
    info = {"proxyMethod": "custom", "proxyCategory": proto,
            "ipType": "IPV4", "protocol": proto,
            "host": p["host"], "port": str(p["port"])}
    if p.get("username"):
        info["proxyUserName"] = p["username"]
        info["proxyPassword"] = p.get("password") or ""
    return info


def _roxy_find_window(name):
    """按名字查窗口 -> (window|None, api_err|None)。
    (None,None)=真不存在; (None,err)=API 调用失败 ——
    调用方据此区分"该建新窗"和"查询挂了"。"""
    cfg = _roxy_cfg()
    r = _roxy_call(f"/browser/list_v3?page_index=1&page_size=100"
                   f"&workspaceId={cfg['workspace_id']}")
    if r.get("error"):
        time.sleep(2)   # API 瞬断兜底重试一次
        r = _roxy_call(f"/browser/list_v3?page_index=1&page_size=100"
                       f"&workspaceId={cfg['workspace_id']}")
    if r.get("error"):
        return None, "Roxy 查询失败: " + r["error"]
    for w in (r.get("data") or {}).get("rows") or []:
        if w.get("windowName") == name:
            return w, None
    return None, None


# 不同窗口不同指纹: 按邮箱哈希在平台池里确定性分配 ——
# 同一账号重建窗口得到同一环境, 账号之间互不相同
_ROXY_OS_POOL = [
    ("macOS", "15.3.2"),
    ("macOS", "14.7.1"),
    ("macOS", "13.7.2"),
    ("Windows", "11"),
    ("Windows", "10"),
]

# Roxy /browser/create osVersion 枚举 (照官方 API 文档)
_ANDROID_VERS = ["15", "14", "13", "12", "11", "10", "9"]
_IOS_VERS = ["18.2", "18.1", "18.0", "17.0", "16.6", "16.5",
             "16.4", "16.3", "16.2", "16.1", "16.0", "15.7",
             "15.6", "15.5", "15.4", "15.3", "15.2", "15.1",
             "15.0", "14.7", "14.6", "14.5", "14.4", "14.3",
             "14.2", "14.1", "14.0"]
_ENV_FIXED = {
    "win11": ("Windows", "11"), "win10": ("Windows", "10"),
    "win8": ("Windows", "8"),   "win7": ("Windows", "7"),
    "mac15": ("macOS", "15.3.2"), "mac14": ("macOS", "14.7.1"),
    "mac13": ("macOS", "13.7.2"), "linux": ("Linux", "ALL"),
}


def _roxy_env_for(email, env=None):
    """建窗指纹环境 (os, osVersion)。
    env=None/'pc-random': PC 池按邮箱哈希 (默认);
    'win11'/'mac15'/... : 固定值;
    'android-*'/'ios-*' : 指定版本 (*=random 时按邮箱确定性取);
    'mob-random': 手机端两族里确定性取。"""
    if not env or env == "pc-random":
        return _ROXY_OS_POOL[zlib.crc32(email.encode())
                             % len(_ROXY_OS_POOL)]
    if env in _ENV_FIXED:
        return _ENV_FIXED[env]
    h = zlib.crc32((env + ":" + email).encode())
    if env == "android-random":
        return ("Android", _ANDROID_VERS[h % len(_ANDROID_VERS)])
    if env == "ios-random":
        return ("IOS", _IOS_VERS[h % len(_IOS_VERS)])
    if env == "mob-random":
        pool = ([("Android", v) for v in _ANDROID_VERS]
                + [("IOS", v) for v in _IOS_VERS])
        return pool[h % len(pool)]
    if env.startswith("android-"):
        v = env[8:]
        if v in _ANDROID_VERS:
            return ("Android", v)
    if env.startswith("ios-"):
        v = env[4:]
        if v in _IOS_VERS:
            return ("IOS", v)
    return _ROXY_OS_POOL[zlib.crc32(email.encode())
                         % len(_ROXY_OS_POOL)]


def _roxy_open_for(email, proxy, kernel="Chrome", prefix="auto",
                   env=None):
    """找到或创建 <prefix>-<email> 窗口并绑定指定代理, 返回 (dirId, ws, err)。
    kernel 只在新建窗口时生效; 已有窗口沿用自己的内核。
    prefix: GPT 账号用 auto-, Google 账号用 gauto- (同邮箱也分窗)。
    env: 建窗指纹环境, None 时读 settings.open_env (默认 pc-random);
    只影响新建窗口, 已存在的窗口指纹不动。"""
    cfg = _roxy_cfg()
    name = f"{prefix}-{email}"
    w, werr = _roxy_find_window(name)
    if werr:
        return None, None, werr
    if w:
        dir_id = w["dirId"]
        pi = (w.get("proxyInfo") or {})
        if pi.get("host") != proxy["host"] or \
                str(pi.get("port")) != str(proxy["port"]):
            _roxy_call("/browser/mdf", {
                "workspaceId": cfg["workspace_id"], "dirId": dir_id,
                "proxyInfo": _roxy_proxyinfo(proxy)})
    else:
        if env is None:
            env = _settings().get("open_env") or "pc-random"
        os_name, os_ver = _roxy_env_for(email, env)
        r = _roxy_call("/browser/create", {
            "workspaceId": cfg["workspace_id"], "windowName": name,
            "os": os_name, "osVersion": os_ver,
            "coreType": kernel,
            "proxyInfo": _roxy_proxyinfo(proxy)}, timeout=60)
        dir_id = (r.get("data") or {}).get("dirId")
        if not dir_id:
            return None, None, r.get("error") or "窗口创建失败"
        _roxy_call("/browser/random_env",
                   {"workspaceId": cfg["workspace_id"], "dirId": dir_id})
    o = _roxy_call("/browser/open",
                   {"workspaceId": cfg["workspace_id"], "dirId": dir_id},
                   timeout=120)
    if o.get("error") and "timed out" in str(o["error"]).lower():
        time.sleep(3)
        o = _roxy_call("/browser/open",
                       {"workspaceId": cfg["workspace_id"],
                        "dirId": dir_id}, timeout=120)
    ws = (o.get("data") or {}).get("ws")
    if not ws:
        return dir_id, None, o.get("error") or "窗口打开失败"
    return dir_id, ws, None


def _roxy_goto_url(ws, url, init_js=None):
    """通过 CDP 让已开的 Roxy 窗口跳转到指定 url。
    init_js 提供时 add_init_script (管后续每次导航) + 当前页 evaluate
    —— 用于 Google 页顶助手条注入。"""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        br = pw.chromium.connect_over_cdp(ws)
        try:
            ctx = br.contexts[0] if br.contexts else None
            pg = (ctx.pages[0] if ctx and ctx.pages
                  else (ctx.new_page() if ctx else None))
            if pg is None:
                raise RuntimeError("拿不到窗口页面")
            if init_js:
                try:
                    pg.add_init_script(init_js)
                except Exception:
                    pass
            pg.goto(url, wait_until="domcontentloaded", timeout=60000)
            if init_js:
                try:
                    pg.evaluate(init_js)
                except Exception:
                    pass
        finally:
            br.close()          # 断开 CDP, 不关浏览器进程


# ---------------- 账号库 ----------------
ACCOUNTS_FILE = os.path.join(BASE_DIR, "accounts.json")
_acct_lock = threading.Lock()


def _load_accounts():
    try:
        return json.load(open(ACCOUNTS_FILE)).get("accounts") or []
    except Exception:
        return []


def _save_accounts(accs):
    with _acct_lock:
        tmp = ACCOUNTS_FILE + ".tmp"
        json.dump({"accounts": accs}, open(tmp, "w"),
                  ensure_ascii=False, indent=1)
        os.replace(tmp, ACCOUNTS_FILE)


# 注意 TLD 限纯字母: [\w-]+ 会把 "com----pass----备注" 整段吞进域名
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


def _parse_account_line(line):
    """一行 -> (dict|None, err|None)。
    email----接码链接 | email----密码----... | email:密码 | email
    email 后的字段: http(s):// 开头=接码链接(mail_url), 否则=密码。"""
    s = line.strip()
    if not s:
        return None, "empty"
    if s.startswith("#"):
        return None, "comment"
    m = _EMAIL_RE.search(s)
    if not m:
        return None, "没有邮箱"
    email = m.group(0).lower()
    password, mail_url, extra, totp = "", "", "", ""

    def _classify(tok):
        nonlocal password, mail_url, extra, totp
        if re.match(r"^https?://", tok, re.I) and not mail_url:
            mail_url = tok
        elif _TOTP_SPACED.match(tok.strip()):
            # 4+ 组带空格的 base32 —— 只会是 TOTP 密钥, 抢占任何槽位
            totp = re.sub(r"\s+", "", tok).lower()
        elif not password:
            password = tok
        elif _TOTP_BARE.match(tok.strip()):
            totp = tok.strip().lower()
        else:
            extra = (extra + "----" + tok) if extra else tok

    if "----" in s or "\t" in s:
        parts = [p.strip() for p in re.split(r"----|\t", s)
                 if p.strip()]
        for i, p in enumerate(parts):
            if email in p:
                tail = p.split(email, 1)[1].lstrip(":").strip()
                for tok in ([tail] if tail else []) + parts[i + 1:]:
                    _classify(tok)
                break
    else:
        tail = s.split(email, 1)[1].lstrip(":").strip()
        if tail:
            _classify(tail)
    return {"email": email, "password": password,
            "mail_url": mail_url, "extra": extra,
            "totp": totp}, None


# Google 2FA TOTP secret: 4-10 组 4 位 base32 带空格
# (wcfn y3q4 ioik 6rh6 ...), 或裸 16/24/32 位 base32
_TOTP_SPACED = re.compile(
    r"^([a-zA-Z2-7]{4}\s+){3,9}[a-zA-Z2-7]{4}$")
_TOTP_BARE = re.compile(r"^[a-zA-Z2-7]{16}$|^[a-zA-Z2-7]{24}$"
                        r"|^[a-zA-Z2-7]{32}$")


def _looks_totp(tok):
    t = tok.strip()
    return bool(_TOTP_SPACED.match(t) or _TOTP_BARE.match(t))


def _totp_code(secret, offset=0):
    """RFC6238 TOTP → 当前 6 位码 (sha1/30s)。失败返回 None。"""
    try:
        key = base64.b32decode(
            re.sub(r"\s+", "", secret).upper())
        c = struct.pack(">Q", int(time.time() // 30) + offset)
        h = hmac.new(key, c, hashlib.sha1).digest()
        o = h[-1] & 0xF
        n = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6
        return "%06d" % n
    except Exception:
        return None


def _new_account(email, password, mail_url="", extra="", totp=""):
    return {"id": "ac_" + uuid.uuid4().hex[:10],
            "email": email, "password": password,
            "mail_url": mail_url, "extra": extra, "totp": totp,
            "proxy_id": None, "win": None, "status": "new",
            "note": "", "created_at": _now()}


# ---------------- 选代理 / 绑定 ----------------
PICK_LIMIT = 3          # 一条代理最多绑几个账号
PICK_LAST = {"cooled": 0}   # 上次 pick 时被冷却拦了几条 (日志用)


def _cool_secs():
    try:
        return int(float(
            _settings().get("proxy_cool_min") or 20) * 60)
    except Exception:
        return 1200


def _touch_cool(p, email, secs=None):
    """账号取用/释放过这条代理 -> 对其他账号进入冷却期。
    同一账号 (bound 里 / 触发冷却的) 豁免。"""
    p["cool_email"] = email
    p["cool_until"] = time.strftime(
        "%Y-%m-%dT%H:%M:%S",
        time.localtime(time.time()
                       + (secs if secs is not None
                          else _cool_secs())))


def _cooling(p, email):
    """email 取这条代理会被冷却拦住吗。"""
    cu = p.get("cool_until")
    if not cu:
        return False
    if email and (email in (p.get("bound") or [])
                  or email == p.get("cool_email")):
        return False          # 同账号/持有人豁免
    return cu > _now()        # iso 串字典序 = 时间序


def _bound_count(p):
    return len(p.get("bound") or [])


def _pick_proxy(px, email=None, limit=PICK_LIMIT, excl=None):
    """未封禁 + 绑定<limit + 非冷却(对 email) + 不在 excl;
    排序: 绑定数 -> 已知失效沉底 -> 最久未用。"""
    cands = [p for p in px if not p.get("banned")
             and _bound_count(p) < limit
             and (not excl or p.get("id") not in excl)]
    avail = [p for p in cands if not _cooling(p, email)]
    PICK_LAST["cooled"] = len(cands) - len(avail)
    avail.sort(key=lambda p: (_bound_count(p),
                              p.get("alive") is False,
                              p.get("last_used") or "1970-01-01"))
    return avail[0] if avail else None


def _bind_proxy(p, email, secs=None):
    bound = p.setdefault("bound", [])
    if email not in bound:
        bound.append(email)
    p["last_used"] = _now()
    _touch_cool(p, email, secs)


def _unbind_proxy(p, email, secs=None):
    bound = p.get("bound") or []
    if email in bound:
        bound.remove(email)
        _touch_cool(p, email, secs)
        return True
    return False


# ---------------- 接码 ----------------
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36")


def _https_status_get(url, upstream=None, timeout=15, headers=None):
    """GET http(s) url 返回 (status_code, body bytes)。
    有上级代理则先建隧道再包 TLS —— 本机无外网时这是唯一出路。
    headers: dict 额外请求头 (如 Authorization)。"""
    u = urllib.parse.urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    if upstream:
        s = _dial_via_upstream(upstream, host, port, timeout)
    else:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
            s.settimeout(timeout)
        extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {u.netloc}\r\n"
                   f"User-Agent: {UA}\r\nAccept: */*\r\n"
                   + extra +
                   f"Connection: close\r\n\r\n").encode())
        data = b""
        while True:
            ch = s.recv(8192)
            if not ch:
                break
            data += ch
        head, _, body = data.partition(b"\r\n\r\n")
        try:
            status = int(head.split(b" ", 2)[1].split(b" ")[0])
        except Exception:
            status = 0
        if b"chunked" in head.lower():        # 简易 dechunk
            out, rest = b"", body
            while True:
                nl = rest.find(b"\r\n")
                if nl < 0:
                    break
                try:
                    n = int(rest[:nl].split(b";")[0].strip(), 16)
                except ValueError:
                    break
                if n == 0:
                    break
                out += rest[nl + 2: nl + 2 + n]
                rest = rest[nl + 2 + n + 2:]
            body = out
        return status, body
    finally:
        try:
            s.close()
        except Exception:
            pass


def _https_get(url, upstream=None, timeout=15, headers=None):
    return _https_status_get(url, upstream, timeout, headers)[1]


def _http_post_json(url, payload, headers=None, upstream=None,
                    timeout=20, method="POST"):
    """JSON 请求, 返回 (status, body bytes)。
    http 直连; https 有上级走隧道。用于本地小模型 OpenAI 兼容接口。"""
    u = urllib.parse.urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    data = json.dumps(payload).encode()
    hs = {"Host": u.netloc, "Content-Type": "application/json",
          "Content-Length": str(len(data)), "Connection": "close"}
    hs.update(headers or {})
    if upstream and u.scheme == "https":
        s = _dial_via_upstream(upstream, host, port, timeout)
    else:
        s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
            s.settimeout(timeout)
        head = "".join(f"{k}: {v}\r\n" for k, v in hs.items())
        s.sendall((f"{method} {path} HTTP/1.1\r\n" + head
                   + "\r\n").encode() + data)
        buf = b""
        while True:
            ch = s.recv(8192)
            if not ch:
                break
            buf += ch
        head_b, _, body = buf.partition(b"\r\n\r\n")
        status = int(head_b.split(b" ", 2)[1]) if \
            b" " in head_b else 0
        if b"chunked" in head_b.lower():
            out, rest = b"", body
            while True:
                nl = rest.find(b"\r\n")
                if nl < 0:
                    break
                try:
                    n = int(rest[:nl].split(b";")[0].strip(), 16)
                except ValueError:
                    break
                if n == 0:
                    break
                out += rest[nl + 2: nl + 2 + n]
                rest = rest[nl + 2 + n + 2:]
            body = out
        return status, body
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------- AI 资料生成 ----------------
NAMEGEN_PROMPT = (
    "你现在是一个人物信息生产助手，你只做2件事：生产人物名称和年龄，"
    "别的不生产，输出格式用逗号分隔，比如 alex,25。"
    "我输入会给你一个邮箱，请你根据邮箱的特征来生产。"
    "例如 falcaonatalia618@gmail.com 可以叫 falcons,31。")


def _gen_profile(email, log):
    """调本地小模型按邮箱特征生成 (名字, 年龄)。未配置/失败返回 None。"""
    s = _settings()
    url = (s.get("namegen_url") or "").strip()
    if not s.get("namegen_enabled") or not url:
        return None
    if not url.endswith("/chat/completions"):
        url = url.rstrip("/") + "/chat/completions"
    payload = {"model": (s.get("namegen_model") or "local-model"),
               "messages": [
                   {"role": "system",
                    "content": (s.get("namegen_prompt")
                                or NAMEGEN_PROMPT)},
                   {"role": "user", "content": email}],
               "temperature": 0.9, "max_tokens": 30,
               "stream": False}
    headers = {}
    if s.get("namegen_key"):
        headers["Authorization"] = "Bearer " + s["namegen_key"]
    up = _upstream() if url.startswith("https://") else None
    try:
        st, body = _http_post_json(url, payload, headers,
                                   upstream=up, timeout=25)
        if st != 200:
            log("  资料生成接口 %d: %s" % (st, body[:100]))
            return None
        j = json.loads(body.decode(errors="ignore"))
        txt = (j["choices"][0]["message"]["content"] or "").strip()
        # 解析 "falcons,31" —— 兼容中文逗号/多余空白/反引号
        m = re.search(r"([A-Za-z][A-Za-z .'’-]{1,28}?)\s*[,，]\s*"
                      r"(\d{1,3})", txt)
        if not m:
            log("  资料生成返回无法解析: %s" % txt[:60])
            return None
        name = re.sub(r"[^A-Za-z ]", "", m.group(1)).strip() \
            .title() or "User"
        age = min(max(int(m.group(2)), 18), 70)
        return name, age
    except Exception as e:
        log("  资料生成失败: %s" % str(e)[:80])
        return None


def _mail_code_once(mail_url, upstream):
    """单次查询接码接口 -> (验证码|None, err|None)。
    err='dead' = 邮箱账号不可用 (code:602), 流程应立即退出。"""
    body = _https_get(mail_url, upstream, 15).decode(errors="ignore")
    j = None
    try:
        j = json.loads(body)
    except Exception:
        pass
    if j is not None:
        if j.get("code") in (502, 602, "502", "602") \
                or "unavailable" in str(j.get("message") or "").lower() \
                or "not found" in str(j.get("message") or "").lower():
            return None, "dead"
        if j.get("code") in (601, "601") or not j.get("data"):
            return None, None                  # Waiting for code
        m = re.search(r"\b(\d{4,8})\b",
                      json.dumps(j["data"], ensure_ascii=False))
        return (m.group(1) if m else None), None
    if "unavailable" in body.lower():
        return None, "dead"
    if "waiting" in body.lower():
        return None, None
    m = re.search(r"\b(\d{4,8})\b", body)
    return (m.group(1) if m else None), None


def _fetch_mail_code(mail_url, upstream, log,
                     timeout=240, interval=5, exclude=(),
                     should_stop=None):
    """轮询接码链接拿新验证码。
    exclude=已知旧码 —— 供应商接口有缓存滞后, 新邮件进来前会把
    上一次的旧码再返回一阵, 必须排除, 否则填旧码被页面拒。"""
    excl = set(exclude)
    deadline = time.time() + timeout
    last_seen = None
    while time.time() < deadline:
        if should_stop and should_stop():
            return None
        try:
            code, err = _mail_code_once(mail_url, upstream)
            if err == "dead":
                return "dead"
            if code:
                last_seen = code
                if code not in excl:
                    return code
        except Exception as e:
            log(f"  取码请求失败: {str(e)[:60]}")
        time.sleep(interval)
    return last_seen       # 兜底: 到超时仍只有旧码也返回, 让页面判定


# ---------------- 接码监听 (半自动模式用) ----------------
# 人工在窗口里注册时, 后台替用户盯接码接口, 出码写到 MAIL_WATCH
# 供前端展示+复制。启动时快照现存的码做基线, 只报新码。
MAIL_WATCH = {}
MAIL_WATCH_TTL = 600      # 监听最长 10 分钟


def _mail_watch(a):
    aid, murl = a["id"], a.get("mail_url")
    up = _upstream()
    seen = set()
    try:
        c0, e0 = _mail_code_once(murl, up)
        if e0 == "dead":
            MAIL_WATCH[aid].update(running=False, dead=True,
                                   ts_done=time.time())
            return
        if c0:
            seen.add(c0)
    except Exception:
        pass
    deadline = time.time() + MAIL_WATCH_TTL
    while time.time() < deadline \
            and not MAIL_WATCH.get(aid, {}).get("stop"):
        try:
            c, e = _mail_code_once(murl, up)
            if e == "dead":
                MAIL_WATCH[aid].update(running=False, dead=True,
                                       ts_done=time.time())
                return
            if c and c not in seen:
                seen.add(c)
                MAIL_WATCH[aid].update(code=c, at=_now())
        except Exception:
            pass
        time.sleep(4)
    MAIL_WATCH.get(aid, {}).update(running=False,
                                   ts_done=time.time())


def _mail_watch_start(a):
    if not a.get("mail_url"):
        return False
    w = MAIL_WATCH.get(a["id"])
    if w and w.get("running"):
        return True
    MAIL_WATCH[a["id"]] = {"email": a["email"], "running": True,
                           "code": None, "at": None,
                           "dead": False, "stop": False}
    threading.Thread(target=_mail_watch, args=(dict(a),),
                     daemon=True).start()
    return True


# 半自动资料预生成: 开窗时后台调 AI 模型生成 姓名+年龄, 面板可复制
PROF_WATCH = {}


def _prof_gen_start(a):
    aid = a["id"]
    PROF_WATCH[aid] = {"email": a["email"], "name": None,
                       "age": None, "at": None, "err": None,
                       "ts": time.time()}

    def _bg():
        import random as _r
        try:
            g = _gen_profile(a["email"], lambda m: None)
            if g:
                PROF_WATCH[aid].update(name=g[0], age=g[1],
                                       at=_now())
            else:
                nm = re.sub(r"[^A-Za-z]", "",
                            a["email"].split("@")[0]).capitalize() \
                    or "User"
                PROF_WATCH[aid].update(
                    name=nm, age=_r.randint(22, 38), at=_now(),
                    err="模型失败, 兜底值")
        except Exception as e:
            PROF_WATCH[aid]["err"] = str(e)[:80]
    threading.Thread(target=_bg, daemon=True).start()
    return True


# ---------------- ChatGPT 登录驱动 ----------------
# 实测 (auth.openai.com 流程):
#   chatgpt.com 点 Log in -> 内嵌弹层 input[name=login_hint]
#   -> 真实点击 Continue -> auth.openai.com/email-verification
#   -> input[name=code] -> 真实点击 Continue -> /about-you (新注册)
# 注意: JS el.click() 是 isTrusted=false, 该站表单会忽略 -> 必须真点击。
EMAIL_INPUT = ("input[name=login_hint],input[name=email],"
               "input[type=email],input#email")
CODE_INPUT = ("input[name=code],input[autocomplete=one-time-code],"
              "input[inputmode=numeric],input[name*=otp]")


def _real_continue(pg):
    """真实点击当前表单的 Continue/submit (不可信 JS click 会被忽略)。"""
    for s in ('button[type=submit]:has-text("Continue")',
              'form:has(input[name=login_hint]) button[type=submit]',
              'form:has(input[name=code]) button[type=submit]',
              'form:has(input[name=name]) button[type=submit]',
              'button[type=submit]:visible'):
        try:
            pg.click(s, timeout=3000)
            return True
        except Exception:
            continue
    try:
        pg.keyboard.press("Enter")
        return True
    except Exception:
        return False


def _page_text(pg, n=400):
    try:
        return pg.evaluate(
            "document.body?document.body.innerText.slice(0,%d):''" % n) or ""
    except Exception:
        return ""


def _looks_verify(pg):
    return bool(re.search(r"verify you are|human|just a moment|"
                          r"checking your|验证你是", _page_text(pg), re.I))


def _email_fill_step(pg, email, log, hdelay, tdelay, stopped=None):
    """chatgpt 落地页 -> 点 Log in -> 等邮箱框 -> 拟人填邮箱。
    不提交 (提交前调用方可能要先做接码基线)。返回 None=ok 或错误串。"""
    def _stopped():
        return bool(stopped and stopped())
    _em = pg.query_selector(EMAIL_INPUT)
    if not (_em and _em.is_visible()):
        # 真实鼠标点击 (JS click 无 pointer 事件, isTrusted=false)
        clicked = False
        for sel in ('button:has-text("Log in")',
                    'a:has-text("Log in")',
                    'text=/^\\s*Log in\\s*$/i'):
            try:
                pg.click(sel, timeout=3000)
                clicked = True
                break
            except Exception:
                continue
        if not clicked:
            clicked = pg.evaluate("""() => {
                const els=[...document.querySelectorAll(
                    'button,a,[role=button]')];
                const b=els.find(e=>/^\\s*(log\\s*in|sign\\s*in|登录|登入)\\s*$/i
                                  .test((e.innerText||'').trim()));
                if(b){b.click();return (b.innerText||'').trim()}
                return null;
            }""")
        if clicked:
            log("  已点登录按钮 (%s)" % str(clicked)[:20])
    try:
        pg.wait_for_selector(EMAIL_INPUT, timeout=20000)
    except Exception:
        if _stopped():
            return "stopped"
        if _looks_verify(pg):
            log("  ⚠ 人机验证 —— 请在窗口里手动完成, 流程继续等")
            pg.wait_for_selector(EMAIL_INPUT, timeout=120000)
        else:
            return "没等到邮箱输入框: " + _page_text(pg)[:80]
    if _stopped():
        return "stopped"
    hdelay()
    try:
        pg.fill(EMAIL_INPUT, "")
    except Exception:
        pass
    pg.click(EMAIL_INPUT)
    pg.type(EMAIL_INPUT, email, delay=tdelay())
    log("  已填入邮箱 %s" % email)
    hdelay()
    return None


# -------- Roxy 窗口页顶助手条 (GPT): 邮箱/密码/实时接码/生成资料 --------
# 码和资料都是后端异步到的 (MAIL_WATCH 接码轮询 / PROF_WATCH AI生成),
# 所以页内脚本每 3s 轮询 /api/helper?email= 拿最新值 (CORS/PNA 已开)。
_HELPER_JS = r"""(()=>{
const E=@E@,ID="__ghbar2",
API="http://127.0.0.1:8322/api/helper?email="+encodeURIComponent(E);
let D={},bar=null,elCd=null,elPw=null,elNm=null,elAg=null,dead=false;
const cp=(t,c)=>{const old=c.textContent;const lg=()=>{const ta=document.createElement("textarea");ta.value=t;ta.style.cssText="position:fixed;opacity:0;top:0";document.body.appendChild(ta);ta.select();try{document.execCommand("copy")}catch(e){}ta.remove()};const ok=()=>{c.textContent="✓ 已复制";setTimeout(()=>{c.textContent=old},900)};if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(ok).catch(()=>{lg();ok()})}else{lg();ok()}};
const chip=(txt,tip,fn,st)=>{const c=document.createElement("span");c.textContent=txt;c.title=tip||"";c.style.cssText="background:rgba(255,255,255,.13);border:1px solid rgba(255,255,255,.28);border-radius:6px;padding:3px 9px;cursor:pointer;white-space:nowrap;font-family:ui-monospace,monospace;font-size:12px"+(st||"");c.addEventListener("click",ev=>{ev.preventDefault();ev.stopPropagation();fn(c)});return c};
const render=()=>{if(!bar)return;
  if(D.password&&!elPw){elPw=chip("密码 •••","复制密码",
    c=>cp(D.password,c));bar.insertBefore(elPw,bar.lastChild)}
  if(elCd){
    if(D.mail_dead){elCd.textContent="邮箱失效";
      elCd.title="接码接口判定该邮箱不可用 (602)"}
    else if(D.code){elCd.textContent="码 "+D.code;
      elCd.title="收到于 "+(D.code_at||"")+" —— 点复制"}
    else{elCd.textContent=D.mail_running?"等码中…":"码 --";
      elCd.title="还没收到验证码"}}
  if(D.name&&elNm){elNm.textContent=D.name;elNm.style.display=""}
  if(D.age!=null&&elAg){elAg.textContent=D.age+"岁";
    elAg.style.display=""}};
const poll=async()=>{try{const r=await fetch(API);
  if(r.ok){const j=await r.json();if(j&&j.found){D=j;render()}}}
catch(e){}};
const mount=()=>{if(dead||document.getElementById(ID)||!document.body)
  return;
  bar=document.createElement("div");bar.id=ID;
  bar.style.cssText="position:fixed;top:0;left:0;right:0;z-index:2147483647;display:flex;align-items:center;gap:8px;padding:6px 10px;background:rgba(15,23,42,.93);color:#e2e8f0;font:13px/1.4 -apple-system,system-ui,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.4);user-select:none";
  const tag=document.createElement("b");tag.textContent="助手";
  tag.style.cssText="color:#7dd3fc;font-size:12px";bar.appendChild(tag);
  if(E)bar.appendChild(chip(E,"复制邮箱",c=>cp(E,c)));
  if(D.password)bar.appendChild(elPw=chip("密码 •••","复制密码",
    c=>cp(D.password,c)));
  elCd=chip("码 --","邮箱验证码 —— 点复制",
    c=>{if(D.code)cp(D.code,c)},";color:#fbbf24");
  bar.appendChild(elCd);
  elNm=chip("","复制姓名",c=>cp(D.name||"",c),
    ";color:#86efac;display:none");bar.appendChild(elNm);
  elAg=chip("","复制年龄",c=>cp(String(D.age||""),c),
    ";color:#86efac;display:none");bar.appendChild(elAg);
  const x=document.createElement("span");x.textContent="×";
  x.title="收起助手条 (页面跳转会再出现)";
  x.style.cssText="margin-left:auto;cursor:pointer;opacity:.65;font-size:15px;padding:0 4px";
  x.addEventListener("click",ev=>{ev.stopPropagation();dead=true;
    bar=null;elCd=elPw=elNm=elAg=null;x.parentNode.remove()});
  bar.appendChild(x);document.body.appendChild(bar);render()};
mount();poll();
setInterval(poll,3000);
setInterval(mount,2500);
})();"""


def _gpt_helper_js(a):
    return _HELPER_JS.replace(
        "@E@", json.dumps(a.get("email") or ""))


def _gpt_inject_helper(pg, a):
    """页顶挂助手条: add_init_script 管后续每次导航重建,
    evaluate 管当前页。"""
    js = _gpt_helper_js(a)
    try:
        pg.add_init_script(js)
    except Exception:
        pass
    try:
        pg.evaluate(js)
    except Exception:
        pass


def _chatgpt_goto(ws, init_js=None):
    """半自动: 把窗口导航到 chatgpt.com; init_js 提供时注入
    页顶助手条 (add_init_script 管后续导航 + 当前页 evaluate)。"""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        br = pw.chromium.connect_over_cdp(ws)
        try:
            ctx = br.contexts[0] if br.contexts else None
            pg = (ctx.pages[0] if ctx and ctx.pages
                  else (ctx.new_page() if ctx else None))
            if pg is None:
                return "拿不到页面"
            if init_js:
                try:
                    pg.add_init_script(init_js)
                except Exception:
                    pass
            if "chatgpt.com" not in (pg.url or ""):
                pg.goto(TARGET_URL, wait_until="domcontentloaded",
                        timeout=60000)
            if init_js:
                try:
                    pg.evaluate(init_js)
                except Exception:
                    pass
            return "ok"
        finally:
            br.close()


def _chatgpt_email_step(ws, a, log, should_stop=None):
    """半自动·自动输入邮箱: 点 Log in -> 填邮箱 -> 提交, 之后交还人工。"""
    import random
    from playwright.sync_api import sync_playwright
    _st = _settings()
    _smin = float(_st.get("pace_step_min") or 2.0)
    _smax = float(_st.get("pace_step_max") or 6.0)
    _tmin = int(_st.get("pace_type_min") or 90)
    _tmax = int(_st.get("pace_type_max") or 240)
    _loadms = int(_st.get("pace_load_ms") or 5000)

    def hdelay(lo=None, hi=None):
        time.sleep(random.uniform(
            lo if lo is not None else _smin,
            hi if hi is not None else _smax))

    def tdelay():
        return random.randint(_tmin, _tmax)

    with sync_playwright() as pw:
        br = pw.chromium.connect_over_cdp(ws)
        try:
            ctx = br.contexts[0] if br.contexts else None
            pg = (ctx.pages[0] if ctx and ctx.pages
                  else (ctx.new_page() if ctx else None))
            if pg is None:
                return "拿不到页面"
            if "chatgpt.com" not in (pg.url or ""):
                pg.goto(TARGET_URL, wait_until="domcontentloaded",
                        timeout=60000)
            pg.wait_for_timeout(_loadms)
            hdelay()
            err = _email_fill_step(pg, a["email"], log,
                                   hdelay, tdelay, should_stop)
            if err:
                return err
            if not _real_continue(pg):
                return "提交按钮点不动"
            log("  ✉ 邮箱已提交 —— 密码/验证码/资料页交给你 ✋")
            return "ok"
        finally:
            br.close()


def _chatgpt_password_step(ws, a, log, should_stop=None, timeout=300):
    """自动·创建密码: 等 input[name=new-password] -> 生成随机密码
    (存账号) -> 填入提交。密码页可能出现在验证码前(由填码步骤内联
    处理)或之后(本步骤兜); about-you/主界面出现即认为无需密码页。
    返回 ok|no_pwd|stopped|err。"""
    import random
    from playwright.sync_api import sync_playwright
    _st = _settings()
    _tmin = int(_st.get("pace_type_min") or 90)
    _tmax = int(_st.get("pace_type_max") or 240)
    _smin = float(_st.get("pace_step_min") or 2.0)
    _smax = float(_st.get("pace_step_max") or 6.0)

    def hdelay():
        time.sleep(random.uniform(_smin, _smax))

    def tdelay():
        return random.randint(_tmin, _tmax)

    _PWD = "input[name=new-password]"
    with sync_playwright() as pw:
        br = pw.chromium.connect_over_cdp(ws)
        try:
            ctx = br.contexts[0] if br.contexts else None
            pg = (ctx.pages[0] if ctx and ctx.pages
                  else (ctx.new_page() if ctx else None))
            if pg is None:
                return "拿不到页面"
            deadline = time.time() + timeout
            while time.time() < deadline:
                if should_stop and should_stop():
                    return "stopped"
                try:
                    el = pg.query_selector(_PWD)
                    if el and el.is_visible():
                        hdelay()
                        pwd = _gen_password()
                        a["password"] = pwd
                        el.click()
                        pg.fill(_PWD, "")
                        pg.type(_PWD, pwd, delay=tdelay())
                        hdelay()
                        if not _real_continue(pg):
                            return "密码页提交按钮点不动"
                        log("  🔑 创建密码页已自动提交 (密码存账号)")
                        return "ok"
                    # about-you / 主界面已现 = 流程越过密码页
                    if pg.query_selector("input[name=name]") \
                            or pg.query_selector(
                                "#prompt-textarea,textarea"):
                        return "no_pwd"
                except Exception:
                    pass
                time.sleep(2)
            return "no_pwd"
        finally:
            br.close()


def _chatgpt_code_step(ws, a, log, upstream, should_stop=None,
                       auto_password=False):
    """自动·填码: 等验证码框 -> 轮询接码接口取新码 -> 填码提交。
    auto_password 时等码途中遇到创建密码页顺手填掉。
    人工若先一步越过码页则自动退出。
    返回 ok|ok_passed|no_mail|email_dead|stopped|err。"""
    import random
    from playwright.sync_api import sync_playwright
    _st = _settings()
    _tmin = int(_st.get("pace_type_min") or 90)
    _tmax = int(_st.get("pace_type_max") or 240)
    _smin = float(_st.get("pace_step_min") or 2.0)
    _smax = float(_st.get("pace_step_max") or 6.0)

    def hdelay():
        time.sleep(random.uniform(_smin, _smax))

    def tdelay():
        return random.randint(_tmin, _tmax)

    def stopped():
        return bool(should_stop and should_stop())

    murl = a.get("mail_url")
    if not murl:
        return "no_mail"
    _PWD = "input[name=new-password]"
    with sync_playwright() as pw:
        br = pw.chromium.connect_over_cdp(ws)
        try:
            ctx = br.contexts[0] if br.contexts else None
            pg = (ctx.pages[0] if ctx and ctx.pages
                  else (ctx.new_page() if ctx else None))
            if pg is None:
                return "拿不到页面"
            # 基线: 排除此刻接口里已有的旧码 (供应商缓存滞后)
            stale = set()
            try:
                c0, e0 = _mail_code_once(murl, upstream)
                if e0 == "dead":
                    return "email_dead"
                if c0:
                    stale.add(c0)
            except Exception:
                pass
            tried = set(stale)
            # 等验证码框 —— 中途可能出现创建密码页 (auto_password
            # 则顺手填掉, 否则留人工), 或人工直接越过码页; 最长等10分钟
            deadline = time.time() + 600
            saw_code = False
            pwd_done = False
            while time.time() < deadline:
                if stopped():
                    return "stopped"
                try:
                    url = pg.url or ""
                    cb = pg.query_selector(CODE_INPUT)
                    if cb and cb.is_visible():
                        saw_code = True
                        break
                    pel = pg.query_selector(_PWD)
                    if pel and pel.is_visible() and auto_password \
                            and not pwd_done:
                        hdelay()
                        pwd = _gen_password()
                        a["password"] = pwd
                        pel.click()
                        pg.fill(_PWD, "")
                        pg.type(_PWD, pwd, delay=tdelay())
                        hdelay()
                        if _real_continue(pg):
                            pwd_done = True
                            log("  🔑 创建密码页已自动提交"
                                " (密码存账号)")
                        continue
                    if not pel:
                        # 无码框也无密码框:
                        #  见过码框后消失 = 人工已越过
                        if saw_code:
                            return "ok_passed"
                        #  已登录主界面 (有聊天输入框) = 无需填码
                        if pg.query_selector(
                                "#prompt-textarea,textarea"):
                            return "ok_passed"
                except Exception:
                    pass
                time.sleep(2)
            else:
                return "没等到验证码框 (超时10min)"
            # 码框就绪: 取新码 -> 填 -> 提交; 被拒则排除已试码再来, 最多4次
            for attempt in range(4):
                if stopped():
                    return "stopped"
                if attempt >= 2:
                    try:
                        pg.click('button:has-text("Resend")', timeout=3000)
                        log("  已点 Resend 触发新邮件")
                        pg.wait_for_timeout(3000)
                    except Exception:
                        pass
                code = _fetch_mail_code(
                    murl, upstream, lambda m: log("  " + m),
                    timeout=240, interval=5, exclude=tried,
                    should_stop=should_stop)
                if code == "dead":
                    return "email_dead"
                if not code:
                    continue
                tried.add(code)
                try:
                    cb = pg.query_selector(CODE_INPUT)
                    if not (cb and cb.is_visible()):
                        if saw_code:
                            return "ok_passed"   # 人工先填了
                        pg.wait_for_selector(CODE_INPUT, timeout=60000)
                    pg.click(CODE_INPUT)
                    pg.type(CODE_INPUT, code, delay=tdelay())
                    log(f"  已填入验证码 {code}")
                    hdelay()
                    if not _real_continue(pg):
                        return "提交按钮点不动"
                    log("  验证码已提交, 观察结果 ...")
                    pg.wait_for_timeout(4000)
                except Exception as e:
                    return "填码操作失败: " + str(e)[:60]
                try:
                    cb2 = pg.query_selector(CODE_INPUT)
                except Exception:
                    return "ok"   # 提交后页面导航中 = 码已接受
                if not (cb2 and cb2.is_visible()):
                    return "ok"
                if re.search(r"incorrect|wrong|invalid|错误",
                             _page_text(pg), re.I):
                    log("  ✗ 页面报验证码错误, 等新码重试")
                    continue
                return "ok"   # 框还在但无报错 -> 留给人工确认
            return "多次填码未通过"
        finally:
            br.close()


def _about_fields(pg):
    """dump about-you 表单字段结构供诊断 (名字/类型/占位/必填)。"""
    try:
        return pg.evaluate(
            "() => [...document.querySelectorAll('form input,"
            "form select,input[name],select,[role=spinbutton]')]"
            ".map(e=>({tag:e.tagName,name:e.name||'',"
            "type:e.type||'',ph:e.placeholder||'',"
            "aria:e.getAttribute('aria-label')||'',"
            "req:!!e.required}))")
    except Exception:
        return []


def _about_fill(pg, name, age, log, hdelay, tdelay):
    """about-you 填姓名+年龄/生日并提交。
    认不出年龄控件就停手留人工 —— 空着提交等于送风控。
    返回 ok|need_human|err。"""
    import random
    fs = _about_fields(pg)
    if fs:
        log("  资料页字段: " + "; ".join(
            "%s[%s:%s]%s" % (f["tag"], f.get("type", ""),
                             f.get("name", ""),
                             "*" if f.get("req") else "")
            for f in fs))
    pg.click("input[name=name]")
    pg.type("input[name=name]", name, delay=tdelay())
    hdelay(1.0, 3.0)
    age = int(age)
    y = time.localtime().tm_year - age
    mm, dd = random.randint(1, 12), random.randint(1, 28)
    filled = None
    # a) 数字年龄框
    for sel in ("input[name=age]", "input[type=number]",
                "input[inputmode=numeric]",
                'input[aria-label*="age" i]',
                'input[aria-label*="old" i]'):
        try:
            el = pg.query_selector(sel)
            if el and el.is_visible():
                el.click()
                pg.type(sel, str(age), delay=tdelay())
                filled = sel
                break
        except Exception:
            pass
    # b) 生日文本框 MM/DD/YYYY
    if not filled:
        for sel in ("input[name=birthday]", "input[name=birthdate]",
                    "input[name=dob]", 'input[name*="birth" i]',
                    'input[placeholder*="MM" i]',
                    'input[aria-label*="birth" i]'):
            try:
                el = pg.query_selector(sel)
                if el and el.is_visible():
                    el.click()
                    # 掩码框自动插斜杠, 只打数字最稳
                    pg.type(sel, "%02d%02d%d" % (mm, dd, y),
                            delay=tdelay())
                    filled = sel
                    break
            except Exception:
                pass
    # c) 三段下拉 月/日/年
    if not filled:
        sels = [s for s in pg.query_selector_all("select")
                if s.is_visible()]
        if len(sels) >= 3:
            try:
                for i, v in enumerate((mm, dd, y)):
                    try:
                        sels[i].select_option(str(v))
                    except Exception:
                        opts = sels[i].evaluate(
                            "e=>[...e.options]"
                            ".map(o=>o.value||o.text)")
                        hit = [o for o in opts if str(v) in o]
                        if not hit:
                            raise
                        sels[i].select_option(hit[0])
                filled = "selects"
            except Exception:
                pass
    if not filled:
        log("  ⚠ 年龄控件认不出, 停在资料页留人工 ——"
            " 空着提交等于送风控")
        return "need_human"
    hdelay()
    if not _real_continue(pg):
        return "资料页提交按钮点不动"
    return "ok"


def _chatgpt_profile_step(ws, a, log, should_stop=None):
    """半自动·自动填资料: 等 about-you 姓名/年龄页 -> 填 -> 提交。
    数据优先取 🤖资料预生成结果 (PROF_WATCH), 其次现场 AI 生成,
    最后邮箱前缀兜底。人工先越过则自动退出。
    返回 ok|ok_passed|stopped|err。"""
    import random
    from playwright.sync_api import sync_playwright
    _st = _settings()
    _tmin = int(_st.get("pace_type_min") or 90)
    _tmax = int(_st.get("pace_type_max") or 240)
    _smin = float(_st.get("pace_step_min") or 2.0)
    _smax = float(_st.get("pace_step_max") or 6.0)

    def hdelay(lo=None, hi=None):
        time.sleep(random.uniform(
            lo if lo is not None else _smin,
            hi if hi is not None else _smax))

    def tdelay():
        return random.randint(_tmin, _tmax)

    def stopped():
        return bool(should_stop and should_stop())

    with sync_playwright() as pw:
        br = pw.chromium.connect_over_cdp(ws)
        try:
            ctx = br.contexts[0] if br.contexts else None
            pg = (ctx.pages[0] if ctx and ctx.pages
                  else (ctx.new_page() if ctx else None))
            if pg is None:
                return "拿不到页面"
            # 等 about-you 姓名框 (人工可能在过密码/验证码页), 最长10min
            deadline = time.time() + 600
            saw_name = False
            while time.time() < deadline:
                if stopped():
                    return "stopped"
                # 接码监听发现邮箱死了 -> 收不到码走不到资料页, 提前退
                if (MAIL_WATCH.get(a["id"]) or {}).get("dead"):
                    return "email_dead"
                try:
                    nm = pg.query_selector("input[name=name]")
                    if nm and nm.is_visible():
                        saw_name = True
                        break
                    # 姓名框出现后消失 / 回到主站 = 人工已越过
                    if saw_name:
                        return "ok_passed"
                    if pg.query_selector("#prompt-textarea,textarea"):
                        return "ok_passed"
                except Exception:
                    pass
                time.sleep(2)
            else:
                return "没等到资料页 (超时10min)"
            # 姓名/年龄: extra > PROF_WATCH 预生成 > 现场AI > 邮箱前缀
            # PROF_WATCH 可能还在生成中, 最多等 15s 拿结果
            name, age, src = None, None, None
            for _ in range(8):
                pv = PROF_WATCH.get(a["id"]) or {}
                if pv.get("name"):
                    name, age = pv["name"], str(pv["age"])
                    src = "AI预生成"
                    break
                if pv.get("err"):
                    break
                time.sleep(2)
            if not name:
                gen = _gen_profile(a["email"], log)
                if gen:
                    name, age, src = gen[0], str(gen[1]), "AI现场生成"
            if not name:
                name = re.sub(r"[^A-Za-z]", "",
                              a["email"].split("@")[0]).capitalize() \
                    or "User"
                age = str(random.randint(22, 38))
                src = "邮箱兜底"
            if (a.get("extra") or "").strip():
                name = a["extra"].strip()
                src += "+extra"
            r = _about_fill(pg, name, age, log, hdelay, tdelay)
            if r == "ok":
                log(f"  📝 资料已填并提交 ({name}, {age}) ← {src}")
            return r
        finally:
            br.close()



# ---------------- PAT 检验 ----------------
# 机制(已实测):
#   母号窗口(chatgpt.com 页面) evaluate fetch:
#     1) GET /api/auth/session?exchange_workspace_token=true
#        &workspace_id=<ws>&reason=setCurrentAccount  → 换 workspace token
#        (就是前端切 workspace 时调的接口, 新 token 带 workspace 声明)
#     2) POST /backend-api/accounts/<ws>/invites 拉子号进空间
#   子号窗口: 刷新页面自动成为成员 → 同样换 workspace token →
#     POST /backend-api/wham/auth-credentials {name, ttl}
#       403 access_token_creation_disabled → 低级
#       401 *_verification_required        → 良好 (要过身份验证)
#       200 + credential_id                → 良好 (直接建成功, 顺手删掉)
PAT_JOB = {"running": False, "log": [], "results": {},
           "stop": False}

_WS_TOKEN_JS = """async (wsid) => {
    const r = await fetch('/api/auth/session?exchange_workspace_token=true'
        + '&workspace_id=' + wsid + '&reason=setCurrentAccount',
        {credentials: 'include'});
    const j = await r.json();
    return j.accessToken || null;
}"""

_INVITE_JS = """async ({ws, emails, fid, sid, seat}) => {
    const s = await fetch('/api/auth/session?exchange_workspace_token=true'
        + '&workspace_id=' + ws + '&reason=setCurrentAccount',
        {credentials: 'include'});
    const tok = (await s.json()).accessToken;
    if (!tok) return {status: 0, code: 'no_token'};
    const H = {'authorization': 'Bearer ' + tok,
               'chatgpt-account-id': ws,
               'content-type': 'application/json'};
    // 席位类型: codex(用量计费) 空间固定 usage_based;
    // 固定席位空间可选 default(标准) / prolite(高级)
    let seatType = seat || 'default';
    try {
        const acc = await (await fetch(
            '/backend-api/accounts/check/v4-2023-04-27',
            {credentials: 'include', headers: H})).json();
        for (const [k,v] of Object.entries(acc.accounts||{})) {
            const a = v.account || {};
            if (a.account_id !== ws) continue;
            const pt = String(a.plan_type || '');
            if (pt.includes('usage_based')
                || a.is_usage_based_seat_enabled === true)
                seatType = 'usage_based';
        }
    } catch (e) {}
    const body = {email_addresses: emails, flow_id: fid,
                  role: 'standard-user', resend_emails: true,
                  submission_id: sid};
    if (seatType) body.seat_type = seatType;
    const r = await fetch('/backend-api/accounts/' + ws + '/invites', {
        method: 'POST', credentials: 'include', headers: H,
        body: JSON.stringify(body)});
    const bodyText = await r.text();
    return {status: r.status, body: bodyText.slice(0, 800),
            seat: seatType};
}"""

# 建 PAT 探针: name 必须有, ttl 是 int 秒 (30 天)
_PAT_PROBE_JS = """async (wsid) => {
    const s = await fetch('/api/auth/session?exchange_workspace_token=true'
        + '&workspace_id=' + wsid + '&reason=setCurrentAccount',
        {credentials: 'include'});
    const sess = await s.json();
    const tok = sess.accessToken;
    if (!tok) return {status: 0, code: 'no_token'};
    const r = await fetch('/backend-api/wham/auth-credentials', {
        method: 'POST', credentials: 'include',
        headers: {'authorization': 'Bearer ' + tok,
                  'chatgpt-account-id': wsid,
                  'content-type': 'application/json'},
        body: JSON.stringify({name: 'pat-probe-' + Date.now(),
                              ttl: 2592000})});
    const raw = await r.text();
    let j = null;
    try { j = JSON.parse(raw); } catch (e) {}
    const d = (j && j.detail) || {};
    const code = d.code || (d.error && d.error.code)
        || (j && j.error && j.error.code) || null;
    const msg = d.message || (d.error && d.error.message)
        || (j && j.error && j.error.message) || '';
    return {status: r.status, code: code,
            msg: String(msg).slice(0, 200),
            raw: raw.slice(0, 600),
            cred: j && (j.credential_id || (j.credential || {}).id)};
}"""

_PAT_DELETE_JS = """async ({ws, cid, tok}) => {
    const r = await fetch('/backend-api/wham/auth-credentials/' + cid, {
        method: 'DELETE', credentials: 'include',
        headers: {'authorization': 'Bearer ' + tok,
                  'chatgpt-account-id': ws}});
    return r.status;
}"""


def _pat_verdict(status, code):
    """判定: good|good_created|low|None(未知/再试)"""
    if status == 200:
        return "good_created"
    if code == "access_token_creation_disabled":
        return "low"
    if code and ("verification" in code or "mfa" in code.lower()
                 or "required" in code):
        return "good"
    return None


def _find_cgpt_page(br):
    for c in br.contexts:
        for q in c.pages:
            if "chatgpt.com" in (q.url or ""):
                return q
    return None


# ---------------- iOS 协议注册 ----------------
# 纯 HTTP 重放 ChatGPT iOS App 注册流 (不开窗):
#   warmup -> authorize -> 提交邮箱 -> 邮箱OTP -> 提交资料 ->
#   /oauth/token (DPoP)。oai-ios-device-check-token 头每号自造
#   (服务端只验头存在, 不验内容/签名 —— ios/dc-token*.txt 已不需要)。
#   账号需 mail_url (接码) + 可用代理; 走账号代理出口。
#   产物存 a.ios = {at, rt, id_token, device_id, ...}, reg="new" how="ios"。
IOS_JOB = {"running": False, "log": [], "results": {},
           "stop": False}

_IOS_DIR = os.path.join(BASE_DIR, "ios")
_IOS_CLIENT_ID = "app_WXrF1LSkiTtfYqiL6XtjygvX"
_IOS_REDIRECT = ("com.openai.chat://auth0.openai.com"
                 "/ios/com.openai.chat/callback")
_IOS_TOKEN_URL = "https://auth.openai.com/oauth/token"
_IOS_NEXT_URL = ("https://auth.openai.com"
                 "/api/first_party_authorize/next")
_IOS_AUTH_URL = "https://auth.openai.com/api/accounts/authorize"
_IOS_SCOPE = ("openid email profile offline_access model.request "
              "model.read organization.read organization.write")
_IOS_PREAUTH_ERR = (
    "APIClient.DeviceCheckError,2: Failed with error 400, "
    "message: Missing or badly formatted authorization token")
_IOS_UA = ("ChatGPT/1.2026.279 (iOS 27.0; iPhone18,3; "
           "build 37999862476)")


def _gen_dc_token():
    """自造 DCDevice token。实测服务端只验 oai-ios-device-check-token
    头存在, 不验内容/签名 —— 照真 token 形态生成即可:
    \\x02\\x00\\x00\\x00\\xa6\\x39 CBOR 头 + 随机体, 2294B ->
    3060 字符 base64 (前缀 AgAAAKY5, 末尾 '=')。每次调用生成新的。"""
    raw = b"\x02\x00\x00\x00\xa6\x39" + os.urandom(2288)
    return base64.b64encode(raw).decode()


class _ChainRelay:
    """本地 HTTP CONNECT 中继: curl → 127.0.0.1:port →
    (上级链 →) 账号代理 → 目标站。
    池代理直连会被 RST, 只能经上级代理链到 (见
    _dial_via_account_proxy)。curl 链不支持 socks前+socks主,
    所以用本地中继把链式隧道包成普通 http 代理给 curl_cffi。"""

    def __init__(self, p, up, timeout=30):
        self.p, self.up, self.timeout = p, up, timeout
        self.dead = False
        import socketserver
        me = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                c = self.request
                c.settimeout(me.timeout)
                try:
                    req = b""
                    while b"\r\n\r\n" not in req and len(req) < 8192:
                        ch = c.recv(4096)
                        if not ch:
                            return
                        req += ch
                    line = req.split(b"\r\n", 1)[0].decode(
                        errors="ignore")
                    m = re.match(r"CONNECT\s+([^\s:]+):(\d+)", line)
                    if not m:
                        c.sendall(b"HTTP/1.1 400 Bad\r\n\r\n")
                        return
                    host, port = m.group(1), int(m.group(2))
                    s = _dial_via_account_proxy(
                        me.p, host, port, me.timeout, me.up)
                    c.sendall(b"HTTP/1.1 200 Connection established"
                              b"\r\n\r\n")
                    me._pipe(c, s)
                except Exception:
                    try:
                        c.sendall(b"HTTP/1.1 502 Upstream\r\n\r\n")
                    except Exception:
                        pass
                    try:
                        c.close()
                    except Exception:
                        pass

        self.srv = socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever,
                         kwargs={"poll_interval": 0.3},
                         daemon=True).start()

    @staticmethod
    def _pipe(a, b):
        """双向转发直到任一侧断开。"""
        import select
        a.setblocking(False)
        b.setblocking(False)
        try:
            while True:
                rl, _, xl = select.select([a, b], [], [a, b], 60)
                if xl or not rl:
                    break
                for s in rl:
                    try:
                        d = s.recv(65536)
                    except Exception:
                        return
                    if not d:
                        return
                    (b if s is a else a).sendall(d)
        except Exception:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except Exception:
                    pass

    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def close(self):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass


class _IosRegistrar:
    """curl_cffi 会话重放 iOS 注册五步流 (DPoP 签名 token 交换)。"""

    def __init__(self, proxy, log, dc_token=None):
        from curl_cffi import requests as _cr
        self.log = log
        self.s = _cr.Session(proxy=proxy or None,
                             impersonate="safari18_0_ios",
                             timeout=40)
        # 无外部 token 则自造 (服务端只验头存在), 每号一枚不重用
        self.dc_token = dc_token or _gen_dc_token()
        self.device_id = str(uuid.uuid4()).upper()
        self.app_sid = str(uuid.uuid4())
        self.session_log_id = str(uuid.uuid4()).upper()
        self.trace = "%s-%s-0" % (uuid.uuid4().hex,
                                  uuid.uuid4().hex[:16])
        b64 = lambda b: base64.urlsafe_b64encode(
            b).decode().rstrip("=")
        self._b64 = b64
        self.code_verifier = b64(os.urandom(48))
        self.state = b64(os.urandom(32))
        from cryptography.hazmat.primitives.asymmetric import ec
        self.dpop_key = ec.generate_private_key(ec.SECP256R1())

    def _jd(self, obj):
        return json.dumps(obj, separators=(",", ":"))

    def headers(self, extra=None):
        h = [("content-type", "application/json"),
             ("accept", "application/json"),
             ("baggage",
              "sentry-environment=production-ios,sentry-org_id=33249,"
              "sentry-public_key=aaedc2eb8e6ef123191aa364274c85db,"
              "sentry-trace-id=%s,sentry-sample_rate=0.1"
              % uuid.uuid4().hex),
             ("oai-package-name", "com.openai.chat")]
        if self.dc_token:
            h.append(("oai-ios-device-check-token",
                      self._jd({"token": self.dc_token})))
        h += [("priority", "u=3"),
              ("oai-device-id", self.device_id),
              ("accept-language", "zh-Hans-CN,zh;q=0.9"),
              ("sentry-trace", self.trace),
              ("oai-app-sid", self.app_sid),
              ("x-request-client-start", "%.3f" % time.time()),
              ("user-agent", _IOS_UA),
              ("oai-client-type", "ios")]
        if extra:
            h += extra
        return h

    def dpop(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils \
            import decode_dss_signature
        b64 = self._b64
        pub = self.dpop_key.public_key().public_numbers()
        jwk = {"crv": "P-256", "kty": "EC",
               "x": b64(pub.x.to_bytes(32, "big")),
               "y": b64(pub.y.to_bytes(32, "big"))}
        signing = (b64(self._jd(
            {"alg": "ES256", "jwk": jwk, "typ": "dpop+jwt"}
        ).encode()) + "." + b64(self._jd(
            {"htm": "POST", "htu": _IOS_TOKEN_URL,
             "iat": int(time.time()),
             "jti": str(uuid.uuid4()).upper()}).encode()))
        sig = self.dpop_key.sign(signing.encode(),
                                 ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig)
        return (signing + "." +
                b64(r.to_bytes(32, "big") + s.to_bytes(32, "big")))

    def warmup(self):
        r = self.s.get(
            "https://ios.chat.openai.com"
            "/public-api/mobile/server_status/v1",
            headers=self.headers())
        self.log("  warmup %d" % r.status_code)

    def authorize(self):
        params = [
            ("client_id", _IOS_CLIENT_ID),
            ("hydra_flow", "condense"),
            ("issuer", "https://auth.openai.com"),
            ("auth_api_migration_enabled", "true"),
            ("scope", _IOS_SCOPE),
            ("preauth_cookie_failed", _IOS_PREAUTH_ERR),
            ("ccaps", "default_otp login_methods"),
            ("auth_session_logging_id", self.session_log_id),
            ("audience", "https://api.openai.com/v1"),
            ("code_challenge", self._b64(
                hashlib.sha256(
                    self.code_verifier.encode()).digest())),
            ("ios_app_display_version", "unknown"),
            ("redirect_uri", _IOS_REDIRECT),
            ("nonce", self._b64(os.urandom(32))),
            ("state", self.state),
            ("requester_metadata_app_version", "1.2026.279"),
            ("screen_hint", "login_or_signup"),
            ("ios_device_id", self.device_id),
            ("response_type", "code"),
            ("code_challenge_method", "S256"),
            ("ios_app_version", "37999862476"),
        ]
        for att in range(1, 4):
            r = self.s.get(_IOS_AUTH_URL, params=params,
                           headers=self.headers())
            cf = r.headers.get("cf-mitigated", "-")
            self.log("  authorize #%d: %d cf=%s"
                     % (att, r.status_code, cf))
            if r.status_code == 200:
                page = (r.json().get("page") or {}).get("type")
                if page != "login_or_signup_start":
                    raise RuntimeError(
                        "authorize 页异常: %s" % page)
                return
            time.sleep(2)
        raise RuntimeError("authorize 一直拿不到 200")

    def next_step(self, body, expect, tag):
        r = self.s.post(_IOS_NEXT_URL, data=self._jd(body),
                        headers=self.headers([("accept", "*/*")]))
        try:
            data = r.json()
        except Exception:
            data = {}
        self.log("  %s: %d type=%s"
                 % (tag, r.status_code, data.get("type")))
        if r.status_code != 200 or data.get("type") != expect:
            raise RuntimeError("%s 失败: %d %s"
                               % (tag, r.status_code,
                                  r.text[:200]))
        return data

    def exchange(self, code):
        body = {"client_id": _IOS_CLIENT_ID,
                "auth_session_logging_id": self.session_log_id,
                "redirect_uri": _IOS_REDIRECT,
                "code_verifier": self.code_verifier,
                "grant_type": "authorization_code",
                "code": code}
        r = self.s.post(_IOS_TOKEN_URL, data=self._jd(body),
                        headers=self.headers(
                            [("accept", "*/*"),
                             ("dpop", self.dpop()),
                             ("oai-uit", "True")]))
        self.log("  token 交换 %d" % r.status_code)
        if r.status_code != 200:
            raise RuntimeError("token 交换失败: %d %s"
                               % (r.status_code, r.text[:200]))
        return r.json()

    def refresh(self, rt):
        """refresh_token 换新 access_token (同 token 端点)。"""
        body = {"client_id": _IOS_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": rt}
        r = self.s.post(_IOS_TOKEN_URL, data=self._jd(body),
                        headers=self.headers(
                            [("accept", "*/*"),
                             ("dpop", self.dpop()),
                             ("oai-uit", "True")]))
        self.log("  refresh %d" % r.status_code)
        if r.status_code != 200:
            raise RuntimeError("refresh 失败: %d %s"
                               % (r.status_code, r.text[:200]))
        return r.json()


def _ios_birthday(age):
    """按年龄生成生日 YYYY-MM-DD (年月随机取)。"""
    import random as _r
    now = time.localtime()
    y = now.tm_year - age
    m, d = _r.randint(1, 12), _r.randint(1, 28)
    return "%04d-%02d-%02d" % (y, m, d)


def _ios_reg_worker(ids):
    IOS_JOB["running"] = True
    IOS_JOB["stop"] = False
    IOS_JOB["log"] = []
    IOS_JOB["results"] = {}

    def log(m):
        IOS_JOB["log"].append(
            "%s %s" % (time.strftime("%H:%M:%S"), m))

    try:
        from curl_cffi import requests as _cr  # noqa: F401
        import cryptography  # noqa: F401
    except ImportError:
        log("✗ 缺依赖: .venv/bin/pip install curl_cffi cryptography")
        IOS_JOB["running"] = False
        return
    log("iOS 协议注册: %d 个账号 (纯接口, 不开窗, "
        "dc-token 每号自造)" % len(ids))
    try:
        for aid in ids:
            if IOS_JOB["stop"]:
                log("⏹ 已手动停止")
                break
            a = next((x for x in _load_accounts()
                      if x["id"] == aid), None)
            if not a:
                continue
            email = a["email"]
            try:
                if not a.get("mail_url"):
                    IOS_JOB["results"][aid] = "没有接码链接"
                    log("✗ %s: 没有接码链接" % email)
                    continue
                # iOS注册不绑定代理 (不占 bound 空位): 取占用最少
                # 的可用代理, 且避开本号上次注册用的那条 (ios_px)
                px = _load_proxies()
                last = a.get("ios_px")
                p = _pick_proxy(px, email,
                                excl={last} if last else None) \
                    or _pick_proxy(px, email)  # 排光则允许复用
                if not p:
                    IOS_JOB["results"][aid] = "没有可用代理"
                    log("✗ %s: 没有可用代理" % email)
                    continue
                p["last_used"] = _now()
                _touch_cool(p, email)   # 他号冷却, 不占 bound 位
                a["ios_px"] = p["id"]
                _save_proxies(px)
                prof = _gen_profile(email, log)
                name = (prof[0] if prof else None) or "John"
                age = prof[1] if prof else 28
                birthday = _ios_birthday(age)
                log("→ %s: %s 代理开跑 (%s, %s)"
                    % (email, p.get("host"), name, birthday))
                relay = _ChainRelay(p, _upstream())
                try:
                    reg = _IosRegistrar(relay.url(), log)
                    reg.warmup()
                    reg.authorize()
                    stale, _ = _mail_code_once(
                        a["mail_url"], _upstream())
                    es = reg.next_step(
                        {"data": {"kind": "username",
                                  "username": {"kind": "email",
                                               "value": email}},
                         "origin_page_type":
                             "login_or_signup_start"},
                        "email_otp_verification", "email")
                    if (es.get("payload") or {}).get(
                            "email_verification_mode") \
                            == "passwordless_login":
                        # OpenAI 侧已有此号 → 走的是登录流,
                        # OTP 后必撞 preauth cookie 死局(409)。
                        # 直接标 reg=yes 跳过, 别浪费接码轮询
                        a["reg"] = "yes"
                        a["reg_how"] = "exists"
                        a["reg_at"] = _now()
                        IOS_JOB["results"][aid] = \
                            "已是注册账号"
                        log("… %s: OpenAI 已有此号"
                            " (passwordless_login), 标记已注册"
                            % email)
                        continue
                    log("  %s: 等 OTP (接码轮询)…" % email)
                    code = _fetch_mail_code(
                        a["mail_url"], _upstream(), log,
                        timeout=240, interval=5,
                        exclude={stale} if stale else (),
                        should_stop=lambda: IOS_JOB["stop"])
                    if code == "dead":
                        a["email_dead"] = True
                        IOS_JOB["results"][aid] = "邮箱失效(602)"
                        log("✗ %s: 邮箱不可用 (602)" % email)
                        continue
                    if not code:
                        IOS_JOB["results"][aid] = "等码超时"
                        log("✗ %s: 等码超时" % email)
                        continue
                    reg.next_step(
                        {"data": {"code": code,
                                  "intent": "validate",
                                  "username_kind": "email"},
                         "origin_page_type":
                             "email_otp_verification"},
                        "about_you", "otp")
                    final = reg.next_step(
                        {"data": {"name": name,
                                  "birthday": birthday,
                                  "is_explicit_consent_required":
                                      False},
                         "origin_page_type": "about_you"},
                        "token_exchange", "profile")
                    grant = (final.get("payload") or {}).get("code")
                    if not grant:
                        raise RuntimeError(
                            "token_exchange 没带授权码: %s"
                            % str(final)[:150])
                    tokens = reg.exchange(grant)
                    from cryptography.hazmat.primitives \
                        import serialization as _ser
                    a["reg"] = "new"
                    a["reg_how"] = "ios"
                    a["reg_at"] = _now()
                    a["ios"] = {
                        "at": tokens.get("access_token"),
                        "rt": tokens.get("refresh_token"),
                        "id_token": tokens.get("id_token"),
                        "expires_in": tokens.get("expires_in"),
                        "earliest_refresh_at":
                            tokens.get("earliest_refresh_at"),
                        "device_id": reg.device_id,
                        "cookies": reg.s.cookies.get_dict(),
                        "dpop": reg.dpop_key.private_bytes(
                            _ser.Encoding.PEM,
                            _ser.PrivateFormat.PKCS8,
                            _ser.NoEncryption()).decode(),
                        "got_at": _now()}
                    IOS_JOB["results"][aid] = "✓ iOS 注册完成"
                    log("✓ %s: iOS 注册完成, token 已存 a.ios"
                        % email)
                finally:
                    relay.close()
            except Exception as e:
                IOS_JOB["results"][aid] = str(e)[:120]
                log("✗ %s: %s" % (email, str(e)[:120]))
            finally:
                accs_all = _load_accounts()
                for x in accs_all:
                    if x["id"] == aid:
                        x.clear(); x.update(a)
                        break
                _save_accounts(accs_all)
    finally:
        IOS_JOB["running"] = False
        log("—— iOS 注册结束 ——"
            + (" (手动停止)" if IOS_JOB["stop"] else ""))


# ---------------- 协议 PAT 检测 (不开窗) ----------------
# 链路: 母号 ws-AT(窗口抓一次) → HTTP 邀请全部邮箱 → 每号 codex
# 客户端 OTP 登录 → workspace/select 选空间 → ws-scoped AT →
# wham/auth-credentials 探针 → _pat_verdict 判定落 a.pat。
# 母号邀请拿不到 AT 时退化 invites/request 申请制 (待批准)。
PROTO_PAT_JOB = {"running": False, "log": [], "results": {},
                 "stop": False}

_CODEX_CLIENT = "app_EMoamEEZ73f0CkXaXp7hrann"
_CODEX_REDIRECT = "http://localhost:1455/auth/callback"
_CODEX_AUTH_URL = "https://auth.openai.com/api/accounts/authorize"
_CODEX_NEXT_URL = ("https://auth.openai.com"
                   "/api/first_party_authorize/next")
_CODEX_WS_SEL = ("https://auth.openai.com"
                 "/api/accounts/workspace/select")
_CODEX_TOKEN_URL = "https://auth.openai.com/oauth/token"


class _CodexLogin:
    """codex 客户端 OTP 登录 (免 devicecheck preauth, chrome 指纹)。"""

    def __init__(self, proxy, log, dc_token=None):
        from curl_cffi import requests as _cr
        self.log = log
        self.s = _cr.Session(proxy=proxy or None,
                             impersonate="chrome", timeout=40)
        self.device_id = str(uuid.uuid4()).lower()
        self.verifier = _b64u(os.urandom(48))
        self.state = _b64u(os.urandom(32))
        self.dc_token = dc_token or _gen_dc_token()
        from cryptography.hazmat.primitives.asymmetric import ec
        self.dk = ec.generate_private_key(ec.SECP256R1())

    def headers(self, extra=None):
        h = [("content-type", "application/json"),
             ("accept", "application/json"),
             ("originator", "codex_cli_rs"),
             ("x-openai-device-resolution", "desktop"),
             ("oai-device-id", self.device_id)]
        if self.dc_token:
            h.append(("oai-ios-device-check-token",
                      json.dumps({"token": self.dc_token})))
        if extra:
            h += extra
        return h

    def dpop(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils \
            import decode_dss_signature
        pub = self.dk.public_key().public_numbers()
        jwk = {"crv": "P-256", "kty": "EC",
               "x": _b64u(pub.x.to_bytes(32, "big")),
               "y": _b64u(pub.y.to_bytes(32, "big"))}
        si = (_b64u(self._jd({"alg": "ES256", "jwk": jwk,
                             "typ": "dpop+jwt"}).encode()) + "." +
              _b64u(self._jd({"htm": "POST",
                             "htu": _CODEX_TOKEN_URL,
                             "iat": int(time.time()),
                             "jti": str(uuid.uuid4()).upper()}
                            ).encode()))
        sig = self.dk.sign(si.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig)
        return si + "." + _b64u(r.to_bytes(32, "big") +
                               s.to_bytes(32, "big"))

    @staticmethod
    def _jd(o):
        return json.dumps(o, separators=(",", ":"))

    def authorize(self, workspace=None):
        params = [
            ("client_id", _CODEX_CLIENT),
            ("response_type", "code"),
            ("redirect_uri", _CODEX_REDIRECT),
            ("code_challenge", _b64u(hashlib.sha256(
                self.verifier.encode()).digest())),
            ("code_challenge_method", "S256"),
            ("state", self.state),
            ("scope", "openid profile email offline_access"),
            ("audience", "https://api.openai.com/v1"),
            ("originator", "codex_cli_rs"),
            ("id_token_add_organizations", "true"),
            ("codex_cli_simplified_flow", "true"),
        ]
        if workspace:
            params.append(("allowed_workspace_id", workspace))
        r = self.s.get(_CODEX_AUTH_URL, params=params,
                       headers=self.headers())
        d = r.json() if r.text else {}
        self.log("   authorize %d page=%s"
                 % (r.status_code,
                    (d.get("page") or {}).get("type")))
        if r.status_code == 200 and d.get("continue_url"):
            return d["continue_url"]           # 已登录会话直接发码
        if r.status_code == 200 and (d.get("page") or {}).get("type") \
                in ("login_start", "login_or_signup_start"):
            return None
        raise RuntimeError("authorize %d %s"
                           % (r.status_code, r.text[:120]))

    def next(self, body, tag):
        r = self.s.post(_CODEX_NEXT_URL, data=self._jd(body),
                        headers=self.headers([("accept", "*/*")]))
        d = r.json() if r.text else {}
        self.log("   next[%s] %d type=%s"
                 % (tag, r.status_code, d.get("type")))
        return r.status_code, d

    def ws_select(self, wid):
        r = self.s.post(_CODEX_WS_SEL,
                        data=self._jd({"workspace_id": wid}),
                        headers=self.headers([("accept", "*/*")]))
        d = r.json() if r.text else {}
        self.log("   ws_select(%s) %d -> %s"
                 % (wid[:8], r.status_code, str(d)[:100]))
        return d

    def exchange(self, redirect_url):
        import urllib.parse
        q = urllib.parse.urlparse(redirect_url).query
        code = urllib.parse.parse_qs(q).get("code", [None])[0]
        if not code:
            raise RuntimeError("continue_url 没带 code")
        body = {"grant_type": "authorization_code",
                "client_id": _CODEX_CLIENT, "code": code,
                "redirect_uri": _CODEX_REDIRECT,
                "code_verifier": self.verifier}
        r = self.s.post(_CODEX_TOKEN_URL, data=self._jd(body),
                        headers=self.headers(
                            [("dpop", self.dpop())]))
        self.log("   exchange %d" % r.status_code)
        if r.status_code != 200:
            raise RuntimeError("token 交换 %d %s"
                               % (r.status_code, r.text[:150]))
        return r.json()


def _jwt_account_id(at):
    """解 JWT payload 取 chatgpt_account_id (个人/空间看 claim)。"""
    try:
        p = at.split(".")[1]
        p += "=" * (-len(p) % 4)
        pay = json.loads(base64.urlsafe_b64decode(p))
        return (pay.get("https://api.openai.com/auth") or {}) \
            .get("chatgpt_account_id")
    except Exception:
        return None


def _mother_ws_at(log):
    """从母号窗口抓 ws-scoped AT (一次, 任务内复用)。"""
    from playwright.sync_api import sync_playwright
    ws_url, err = _mother_open()
    if err:
        return None, err
    try:
        with sync_playwright() as pw:
            br = pw.chromium.connect_over_cdp(ws_url)
            pg = _find_cgpt_page(br)
            if not pg:
                return None, "母号页不在 chatgpt.com"
            tok = pg.evaluate(_WS_TOKEN_JS,
                              (_settings().get("mother_workspace")
                               or "").strip())
            try:
                br.close()
            except Exception:
                pass
            return tok, None if tok else "窗口没取到 AT"
    except Exception as e:
        return None, str(e)[:100]


def _http_invite(mother_at, ws, emails, proxy, log):
    """母号侧纯 HTTP 邀请 (seat_type 探测同窗口版)。"""
    from curl_cffi import requests as _cr
    s = _cr.Session(proxy=proxy or None, impersonate="chrome",
                    timeout=40)
    h = {"authorization": "Bearer " + mother_at,
         "chatgpt-account-id": ws,
         "content-type": "application/json",
         "accept": "application/json"}
    seat = "usage_based"
    try:
        acc = s.get("https://chatgpt.com/backend-api/accounts"
                    "/check/v4-2023-04-27", headers=h).json()
        for v in (acc.get("accounts") or {}).values():
            ac = v.get("account") or {}
            if ac.get("account_id") != ws:
                continue
            pt = str(ac.get("plan_type") or "")
            if "usage_based" not in pt \
                    and not ac.get("is_usage_based_seat_enabled"):
                seat = "default"
    except Exception:
        pass
    body = {"email_addresses": emails, "flow_id": str(uuid.uuid4()),
            "role": "standard-user", "resend_emails": True,
            "submission_id": str(uuid.uuid4()), "seat_type": seat}
    r = s.post("https://chatgpt.com/backend-api/accounts/%s/invites"
               % ws, data=json.dumps(body), headers=h)
    log("   invite %d seat=%s %s"
        % (r.status_code, seat, r.text[:120]))
    return r.status_code


def _pat_probe_http(at, ws, proxy, log):
    """纯 HTTP wham 探针 + 判定 + 建成即删。"""
    from curl_cffi import requests as _cr
    s = _cr.Session(proxy=proxy or None, impersonate="chrome",
                    timeout=40)
    h = {"authorization": "Bearer " + at,
         "chatgpt-account-id": ws,
         "content-type": "application/json",
         "accept": "application/json",
         "originator": "codex_cli_rs"}
    r = s.post("https://chatgpt.com/backend-api/wham/"
               "auth-credentials",
               data=json.dumps({"name": "pat-probe-%d"
                                        % int(time.time()),
                                "ttl": 2592000}), headers=h)
    raw = r.text[:600]
    try:
        j = r.json()
    except Exception:
        j = {}
    d = j.get("detail") or {}
    code = d.get("code") or (d.get("error") or {}).get("code") \
        or (j.get("error") or {}).get("code")
    raw2 = re.sub(r'("(?:token|credential|secret|value)"\s*:\s*")'
                  r'[^"]{6}', r'\1***', raw, flags=re.I)
    raw2 = re.sub(r'sk-[A-Za-z0-9_-]{4,}', 'sk-***', raw2)
    log("   探针 %d %s | %s"
        % (r.status_code, code or "-",
           raw2[:200].replace("\n", " ")))
    verdict = _pat_verdict(r.status_code, code)
    if verdict == "good_created":
        cid = j.get("credential_id") \
            or (j.get("credential") or {}).get("id")
        if cid:
            r2 = s.delete("https://chatgpt.com/backend-api/wham/"
                          "auth-credentials/" + cid, headers=h)
            log("   清理 PAT %s.. -> %d" % (cid[:8], r2.status_code))
        verdict = "good"
    return verdict or "unknown:%d/%s" % (r.status_code, code)


def _proto_pat_worker(ids):
    PROTO_PAT_JOB["running"] = True
    PROTO_PAT_JOB["stop"] = False
    PROTO_PAT_JOB["log"] = []
    PROTO_PAT_JOB["results"] = {}

    def log(m):
        PROTO_PAT_JOB["log"].append(
            "%s %s" % (time.strftime("%H:%M:%S"), m))

    try:
        from curl_cffi import requests as _cr  # noqa: F401
        import cryptography  # noqa: F401
    except ImportError:
        log("✗ 缺依赖: curl_cffi/cryptography")
        PROTO_PAT_JOB["running"] = False
        return
    st = _settings()
    ws_id = (st.get("mother_workspace") or "").strip()
    ws_name = st.get("mother_workspace_name") or ""
    if not ws_id:
        log("✗ 未配置 PAT 母号空间 (settings.mother_workspace)")
        PROTO_PAT_JOB["running"] = False
        return
    # 先抓母号 ws-AT (一次抓, 整个任务复用; 失败走申请制)
    mother_at, merr = _mother_ws_at(log)
    if mother_at:
        log("母号 ws-AT 已取 (%s), 纯HTTP邀请" % ws_name or ws_id[:8])
    else:
        log("母号窗口不可用 (%s), 子号改走 invites/request 申请"
            % (merr or "-"))
    accs0 = {x["id"]: x for x in _load_accounts()}
    emails = {aid: accs0[aid]["email"] for aid in ids
              if aid in accs0}
    # 有母号 AT 就先把所有邮箱一次性邀请进去 (纯HTTP, 不发邀请邮件
    # 等待 —— pending invite 在子号登录选空间时自动接受)
    if mother_at:
        try:
            up = _upstream()
            _http_invite(mother_at, ws_id, list(emails.values()),
                         _proxy_url(up, "url") if up else None,
                         log)
        except Exception as e:
            log("   批量邀请失败: %s (子号逐个再走申请)"
                % str(e)[:80])
    try:
        for aid in ids:
            if PROTO_PAT_JOB["stop"]:
                log("⏹ 已手动停止")
                break
            a = next((x for x in _load_accounts()
                      if x["id"] == aid), None)
            if not a:
                continue
            email = a["email"]
            try:
                if not a.get("mail_url"):
                    PROTO_PAT_JOB["results"][aid] = "没有接码链接"
                    log("✗ %s: 没有接码链接" % email)
                    continue
                px = _load_proxies()
                p = next((x for x in px
                          if x["id"] == a.get("proxy_id")), None)
                if not p or p.get("banned"):
                    p = _pick_proxy(px, email)
                    if not p:
                        PROTO_PAT_JOB["results"][aid] = "没有可用代理"
                        log("✗ %s: 没有可用代理" % email)
                        continue
                    _bind_proxy(p, email)
                    a["proxy_id"] = p["id"]
                    _save_proxies(px)
                log("→ %s: codex 登录 (%s)" % (email, p["host"]))
                relay = _ChainRelay(p, _upstream())
                try:
                    lg = _CodexLogin(relay.url(), log)
                    lg.authorize()
                    stale, _ = _mail_code_once(
                        a["mail_url"], _upstream())
                    lg.next({"data": {"kind": "username",
                                      "username": {"kind": "email",
                                                   "value": email}},
                             "origin_page_type": "login_start"},
                            "email")
                    code = _fetch_mail_code(
                        a["mail_url"], _upstream(), log,
                        timeout=240, interval=5,
                        exclude={stale} if stale else (),
                        should_stop=lambda: PROTO_PAT_JOB["stop"])
                    if not code or code == "dead":
                        PROTO_PAT_JOB["results"][aid] = \
                            "邮箱失效" if code == "dead" else "等码超时"
                        continue
                    sc, d = lg.next(
                        {"data": {"code": code, "intent": "validate",
                                  "username_kind": "email"},
                         "origin_page_type":
                             "email_otp_verification"}, "otp")
                    if d.get("type") == "add_phone":
                        PROTO_PAT_JOB["results"][aid] = \
                            "blocked:add_phone"
                        log("✗ %s: add_phone 硬门" % email)
                        continue
                    if d.get("type") not in ("token_exchange", None) \
                            and not d.get("continue_url"):
                        d = lg.ws_select(ws_id)
                    redir = d.get("continue_url") or \
                        (d.get("payload") or {}).get(
                            "login_session", {}).get("redirect_url")
                    if not redir:
                        raise RuntimeError(
                            "otp 后无跳转: " + str(d)[:150])
                    tok = lg.exchange(redir)
                    at = tok["access_token"]
                    scope = _jwt_account_id(at)
                    # 个人态 → 选空间 (pending invite 自动接受)
                    if scope != ws_id:
                        if mother_at:
                            pass      # 任务级已邀请
                        else:
                            # 无母号 → 子号主动申请加入
                            h = {"authorization": "Bearer " + at,
                                 "chatgpt-account-id": scope or "",
                                 "content-type":
                                     "application/json"}
                            r = lg.s.post(
                                "https://chatgpt.com/backend-api/"
                                "accounts/%s/invites/request" % ws_id,
                                data="{}", headers=h)
                            log("   invites/request %d %s"
                                % (r.status_code, r.text[:100]))
                            PROTO_PAT_JOB["results"][aid] = \
                                "已申请待批准"
                            continue
                        sel = lg.ws_select(ws_id)
                        redir = sel.get("continue_url") or \
                            (sel.get("payload") or {}).get(
                                "login_session", {}).get(
                                "redirect_url")
                        if not redir:
                            # 再试带 allowed_workspace_id 重授权
                            redir = lg.authorize(ws_id)
                        if not redir:
                            raise RuntimeError("选空间失败")
                        tok = lg.exchange(redir)
                        at = tok["access_token"]
                        scope = _jwt_account_id(at)
                    verdict = _pat_probe_http(at, ws_id,
                                              relay.url(), log)
                    a["pat"] = verdict
                    a["pat_at"] = _now()
                    a["ws_id"] = ws_id
                    _ws_list_add(a, ws_id, ws_name,
                                 "standard-user")
                    if verdict != "窗口未登录" and not a.get("reg"):
                        a["reg"] = "yes"
                        a["reg_at"] = a.get("reg_at") or _now()
                    PROTO_PAT_JOB["results"][aid] = verdict
                    tag = {"good": "✓ 良好", "low": "✗ 低级"} \
                        .get(verdict, "? " + verdict)
                    log("%s %s" % (tag, email))
                finally:
                    relay.close()
            except Exception as e:
                PROTO_PAT_JOB["results"][aid] = str(e)[:120]
                log("✗ %s: %s" % (email, str(e)[:120]))
            finally:
                accs_all = _load_accounts()
                for x in accs_all:
                    if x["id"] == aid:
                        x.clear(); x.update(a)
                        break
                _save_accounts(accs_all)
    finally:
        PROTO_PAT_JOB["running"] = False
        log("—— 协议PAT 结束 ——"
            + (" (手动停止)" if PROTO_PAT_JOB["stop"] else ""))


def _gen_password(n=14):
    """随机密码: 大小写+数字+符号, 各类至少一个, 洗牌防规律性"""
    import random as _r
    import string as _s
    pools = [_s.ascii_lowercase, _s.ascii_uppercase,
             _s.digits, "!@#$%*"]
    pwd = [_r.choice(p) for p in pools]
    pwd += [_r.choice("".join(pools))
            for _ in range(n - len(pools))]
    _r.shuffle(pwd)
    return "".join(pwd)


def _mother_open(name=None):
    """打开母号窗口, 返回 (ws_url, err)。
    name=None 时用设置里的 Pat测试母号窗口名。"""
    name = (name or _settings().get("mother_window") or "").strip()
    if not name:
        return None, "未配置母号窗口名"
    w, werr = _roxy_find_window(name)
    if not w:
        return None, werr or ("Roxy 里找不到窗口 " + name)
    o = _roxy_call("/browser/open",
                   {"workspaceId": _roxy_cfg()["workspace_id"],
                    "dirId": w["dirId"]}, timeout=120)
    ws = (o.get("data") or {}).get("ws")
    if not ws:
        return None, o.get("error") or "母号窗口打开失败"
    return ws, None


_WS_LIST_JS = """async () => {
    const s = await fetch('/api/auth/session', {credentials:'include'});
    const sess = await s.json();
    const tok = sess.accessToken;
    if (!tok) return {error: '未登录'};
    const r = await fetch('/backend-api/accounts/check'
        + '/v4-2023-04-27', {credentials:'include',
        headers:{authorization:'Bearer '+tok}});
    const acc = await r.json();
    const list = [];
    for (const [k,v] of Object.entries(acc.accounts||{})) {
        const a = v.account || {};
        if (a.structure !== 'workspace') continue;
        if (list.find(x => x.id === a.account_id)) continue;
        list.push({id: a.account_id, name: a.name,
                   role: a.account_user_role, plan: a.plan_type});
    }
    return {email: sess.user?.email, workspaces: list};
}"""


def _list_workspaces(win_name):
    """连指定窗口名列出它的 workspace, 返回 (email, [ws], err)。"""
    ws_url, err = _mother_open(win_name)
    if err:
        return None, None, err
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            br = pw.chromium.connect_over_cdp(ws_url)
            try:
                pg = _find_cgpt_page(br)
                if not pg:
                    return None, None, \
                        "窗口里没有 chatgpt.com 页面 —— 请先登录"
                out = pg.evaluate(_WS_LIST_JS)
                if out.get("error"):
                    return None, None, out["error"]
                return out.get("email"), \
                    out.get("workspaces") or [], None
            finally:
                br.close()
    except Exception as e:
        return None, None, str(e)[:200]


# 母号空间账单: 席位价(新增1席) + 续费时间 + 当前席位 —— 只读 preview 不动订阅
_BILLING_JS = """async (wsId) => {
    const J = async (u, h) => {
        const r = await fetch(u, {credentials:'include', headers: h||{}});
        const t = await r.text();
        let j = null; try { j = JSON.parse(t); } catch(e) {}
        return {ok: r.ok, status: r.status, j, t};
    };
    const s = await J('/api/auth/session?exchange_workspace_token=true'
        + '&workspace_id=' + wsId + '&reason=setCurrentAccount');
    const tok = s.j && s.j.accessToken;
    if (!tok) return {error: '拿不到空间 token'};
    const H = {authorization: 'Bearer ' + tok,
               'chatgpt-account-id': wsId};
    const p0 = await J('/backend-api/subscriptions/update/preview'
        + '?account_id=' + wsId + '&updated_seats=3', H);
    if (!p0.ok) return {error: '预览失败 ' + p0.status + ': '
        + String(p0.t || '').slice(0, 150)};
    const cur = Number(p0.j && p0.j.current_seat_quantity);
    if (!cur) return {error: '预览未返回当前席位数',
        detail: JSON.stringify(p0.j || {}).slice(0, 300)};
    const p1 = await J('/backend-api/subscriptions/update/preview'
        + '?account_id=' + wsId + '&updated_seats=' + (cur + 1), H);
    if (!p1.ok) return {error: '预览失败 ' + p1.status + ': '
        + String(p1.t || '').slice(0, 150)};
    const p = p1.j || {};
    const ad = (p.amount_due && typeof p.amount_due === 'object')
        ? p.amount_due : {};
    return {ok: true, seats: cur,
            amount: ad.amount ?? p.total_amount ?? null,
            currency: String(p.currency || ad.currency || '')
                .toUpperCase(),
            renewal: p.renewal_date || p.next_billing_date || ''};
}"""

_CCY_SYM = {"USD": "$", "EUR": "€", "GBP": "£", "CNY": "¥",
            "JPY": "JP¥", "HKD": "HK$"}
_CCY_MINOR0 = {"BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW",
               "MGA", "PYG", "RWF", "VND", "VUV", "XAF", "XOF", "XPF"}
_CCY_MINOR3 = {"BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"}
_CCY_MINOR4 = {"CLF", "UYW"}


def _fmt_ccy(minor_amount, currency):
    """预览接口的 amount 是最小单位 (cent) -> 格式化主单位价。"""
    if minor_amount is None or not currency:
        return ""
    unit = 0 if currency in _CCY_MINOR0 else \
        3 if currency in _CCY_MINOR3 else \
        4 if currency in _CCY_MINOR4 else 2
    amt = minor_amount / (10 ** unit)
    return "%s%.2f" % (_CCY_SYM.get(currency, currency + " "), amt)


def _mother_billing(name, ws_id=""):
    """连母号窗口读她空间的账单。返回 (dict, err):
    {seats, price, currency, renewal, days, ws_id, ws_name}"""
    ws_url, err = _mother_open(name)
    if err:
        return None, err
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            br = pw.chromium.connect_over_cdp(ws_url)
            try:
                pg = _find_cgpt_page(br)
                if not pg:
                    return None, "窗口里没有 chatgpt.com 页面 —— 请先登录"
                ws_name = ""
                if not ws_id:
                    out = pg.evaluate(_WS_LIST_JS)
                    wss = out.get("workspaces") or []
                    own = [w for w in wss
                           if "owner" in (w.get("role") or "")]
                    pick = (own or wss or [None])[0]
                    if not pick:
                        return None, "母号没有任何空间"
                    ws_id, ws_name = pick["id"], pick.get("name") or ""
                r = pg.evaluate(_BILLING_JS, ws_id)
                if not isinstance(r, dict):
                    return None, "账单读取返回异常"
                if r.get("error"):
                    return None, r["error"]
                days = None
                left_min = None
                renewal_ts = None
                renewal = r.get("renewal") or ""
                if renewal:
                    try:
                        dt = datetime.datetime.fromisoformat(
                            renewal.replace("Z", "+00:00"))
                        now = (datetime.datetime.now(dt.tzinfo)
                               if dt.tzinfo
                               else datetime.datetime.now())
                        delta = dt - now
                        left_min = int(delta.total_seconds() // 60)
                        days = delta.days
                        renewal_ts = int(dt.timestamp())
                        bj = dt.astimezone(BJ_TZ) if dt.tzinfo else dt
                        renewal = bj.strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        pass
                return {"seats": r.get("seats"),
                        "price": _fmt_ccy(r.get("amount"),
                                          r.get("currency")),
                        "currency": r.get("currency") or "",
                        "renewal": renewal, "days": days,
                        "left_min": left_min,
                        "renewal_ts": renewal_ts,
                        "ws_id": ws_id, "ws_name": ws_name,
                        "at": _now()}, None
            finally:
                br.close()
    except Exception as e:
        return None, str(e)[:200]


# 子号侧: 检查是否已经是某空间成员
_MEMBER_CHECK_JS = """async (ws) => {
    const s = await fetch('/api/auth/session', {credentials:'include'});
    const sess = await s.json();
    const tok = sess.accessToken;
    if (!tok) return {code:'no_token'};
    const r = await fetch('/backend-api/accounts/check'
        + '/v4-2023-04-27', {credentials:'include',
        headers:{authorization:'Bearer '+tok}});
    const acc = await r.json();
    for (const [k,v] of Object.entries(acc.accounts||{})) {
        const a = v.account||{};
        if (a.account_id === ws)
            return {found:true, role:a.account_user_role||'',
                    name:a.name||''};
    }
    return {found:false};
}"""

# 子号侧: 找 pending 邀请并走 API 接受
_ACCEPT_INVITE_JS = """async (ws) => {
    const s = await fetch('/api/auth/session', {credentials:'include'});
    const sess = await s.json();
    const tok = sess.accessToken;
    if (!tok) return {ok:false, code:'no_token'};
    const H = {'authorization':'Bearer '+tok,
               'content-type':'application/json'};
    const acc = await (await fetch(
        '/backend-api/accounts/check/v4-2023-04-27',
        {credentials:'include', headers:H})).json();
    const entries = Object.values(acc.accounts||{})
        .map(v => v.account||{});
    const me = entries.find(a => a.structure === 'personal')
               || entries[0] || {};
    const pid = me.account_id;
    const tried = [];
    if (pid) {
        const r = await fetch('/backend-api/accounts/' + pid
            + '/invites', {credentials:'include', headers:H});
        tried.push('list:' + r.status);
        if (r.ok) {
            let j = null; try { j = await r.json(); } catch(e) {}
            const items = (j && (j.invites || j.items))
                          || (Array.isArray(j) ? j : []);
            for (const inv of items) {
                const iid = inv.id || inv.invite_id;
                const iw = inv.workspace_id || inv.account_id
                    || (inv.account && inv.account.account_id);
                if (iw && iw !== ws) continue;
                if (!iid) continue;
                for (const u of [
                    '/backend-api/accounts/' + pid
                        + '/invites/' + iid + '/accept',
                    '/backend-api/invites/' + iid + '/accept']) {
                    const ar = await fetch(u, {method:'POST',
                        credentials:'include', headers:H, body:'{}'});
                    tried.push('accept:' + ar.status);
                    if (ar.ok) return {ok:true, how:'api'};
                }
            }
        }
    }
    return {ok:false, tried};
}"""

# 子号侧: 退出指定空间 (HAR: DELETE accounts/{ws}/users/{自己uid})
# 先换目标空间 token —— 窗口当前停在哪个空间无所谓,
# exchange_workspace_token 拿到的就是该空间的 AT
_LEAVE_WS_JS = """async (wsid) => {
    const s = await fetch('/api/auth/session'
        + '?exchange_workspace_token=true&workspace_id=' + wsid
        + '&reason=setCurrentAccount', {credentials:'include'});
    const sess = await s.json();
    const tok = sess.accessToken;
    const uid = (sess.user || {}).id;
    if (!tok) return {status:0, code:'no_token'};
    if (!uid) return {status:0, code:'no_uid'};
    const H = {'authorization':'Bearer '+tok,
               'chatgpt-account-id':wsid,
               'content-type':'application/json'};
    let mine = null, list = [];
    try {
        const acc = await (await fetch(
            '/backend-api/accounts/check/v4-2023-04-27',
            {credentials:'include', headers:H})).json();
        for (const [k,v] of Object.entries(acc.accounts||{})) {
            const a = v.account||{};
            if (a.structure !== 'workspace') continue;
            list.push({id:a.account_id, name:a.name});
            if (a.account_id === wsid) mine = a;
        }
    } catch (e) {}
    if (!mine) return {status:0, code:'not_member', list};
    if (/owner/i.test(String(mine.account_user_role||''))) {
        try {
            const oc = await (await fetch(
                '/backend-api/accounts/' + wsid
                + '/users/owner_count',
                {credentials:'include', headers:H})).json();
            if ((oc.owner_count||0) <= 1)
                return {status:0, code:'sole_owner', list};
        } catch (e) {}
    }
    const r = await fetch('/backend-api/accounts/' + wsid
        + '/users/' + uid, {method:'DELETE',
        credentials:'include', headers:H});
    return {status:r.status, name:mine.name||'', uid,
            body:(await r.text()).slice(0,400)};
}"""


def _pat_worker(ids):
    PAT_JOB["running"] = True
    PAT_JOB["stop"] = False
    PAT_JOB["log"] = []
    PAT_JOB["results"] = {}

    def log(m):
        line = "%s %s" % (time.strftime("%H:%M:%S"), m)
        PAT_JOB["log"].append(line)

    from playwright.sync_api import sync_playwright
    st = _settings()
    ws_id = (st.get("mother_workspace") or "").strip()
    mname = (st.get("mother_window") or "").strip()
    try:
        if not mname or not ws_id:
            log("✗ 未配置母号 (设置里填窗口名 + 选空间)")
            for i in ids:
                PAT_JOB["results"][i] = "未配置母号"
            return
        # 1) 母号窗口开好 (整个任务复用一次连接)
        mws, err = _mother_open()
        if err:
            log("✗ 母号窗口: " + err)
            for i in ids:
                PAT_JOB["results"][i] = "母号: " + err
            return
        log("母号窗口 %s 已连, 空间 %s" % (mname, ws_id[:8]))
        with sync_playwright() as pw:
            mbr = pw.chromium.connect_over_cdp(mws)
            mpg = _find_cgpt_page(mbr)
            if not mpg:
                mpg = mbr.contexts[0].new_page()
                mpg.goto("https://chatgpt.com",
                         wait_until="domcontentloaded", timeout=60000)
                mpg.wait_for_timeout(4000)
            # 2) 母号批量邀请 —— 一次请求拉全部子号进空间
            #    (email_addresses 本就是数组; 401/token过期 →
            #    刷新母号页重取 at, 最多 3 次)
            emails = {}
            for aid in ids:
                a = next((x for x in _load_accounts()
                          if x["id"] == aid), None)
                if a:
                    emails[aid] = a["email"]
            r = {}
            for att in range(3):
                r = mpg.evaluate(_INVITE_JS, {
                    "ws": ws_id, "emails": list(emails.values()),
                    "fid": str(uuid.uuid4()),
                    "sid": str(uuid.uuid4()),
                    "seat": "usage_based"})   # PAT 固定 codex 席
                if r.get("status") == 401 \
                        or "token_expired" in (r.get("body") or ""):
                    log(f"  母号 token 过期, 刷新页面重取 ({att + 1}/3)")
                    try:
                        mpg.goto(TARGET_URL,
                                 wait_until="domcontentloaded",
                                 timeout=60000)
                        mpg.wait_for_timeout(4000)
                    except Exception:
                        pass
                    continue
                break
            if r.get("status") == 401 \
                    or "token_expired" in (r.get("body") or "") \
                    or r.get("code") == "no_token":
                log("✗ 母号会话已失效 —— 请在母号窗口重新登录后再跑")
                for i2 in ids:
                    PAT_JOB["results"][i2] = "母号未登录"
                return
            if r.get("status") != 200:
                log(f"✗ 批量邀请失败 {r.get('status')} "
                    f"{(r.get('body') or '')[:150]}")
                for i2 in ids:
                    PAT_JOB["results"][i2] = \
                        "邀请失败 %s" % r.get("status")
                return
            try:
                bj = json.loads(r.get("body") or "{}")
            except Exception:
                bj = {}
            already = set(bj.get("already_member_emails") or [])
            new_cnt = len(emails) - len(already & set(emails.values()))
            log(f"→ 批量邀请完成: 新发 {new_cnt} 个, "
                f"已是成员 {len(emails) - new_cnt} 个")
            for aid in ids:
                if PAT_JOB["stop"]:
                    log("⏹ 已手动停止")
                    break
                a = next((x for x in _load_accounts()
                          if x["id"] == aid), None)
                if not a:
                    continue
                email = a["email"]
                try:
                    # 3) 子号窗口: 保证绑了代理并打开
                    px = _load_proxies()
                    p = next((x for x in px
                              if x["id"] == a.get("proxy_id")), None)
                    if not p or p.get("banned"):
                        p = _pick_proxy(px, email)
                        if not p:
                            cool = (" (冷却中 %d 条)"
                                    % PICK_LAST["cooled"]
                                    if PICK_LAST["cooled"] else "")
                            PAT_JOB["results"][aid] = \
                                "没有可用代理" + cool
                            log(f"✗ {email}: 没有可用代理{cool}")
                            continue
                        _bind_proxy(p, email)
                        a["proxy_id"] = p["id"]
                        _save_proxies(px)
                    dir_id, cws, err = _roxy_open_for(email, p)
                    if err or not cws:
                        PAT_JOB["results"][aid] = "开窗: " + (err or "")
                        log(f"✗ {email}: 开窗失败 {err}")
                        continue
                    a["win"] = dir_id
                    cbr = pw.chromium.connect_over_cdp(cws)
                    try:
                        cpg = _find_cgpt_page(cbr)
                        if not cpg:
                            cpg = cbr.contexts[0].new_page()
                        # 4) 刷新落成员身份 + 换 workspace token + 建 PAT 探针
                        verdict = None
                        for retry in range(3):
                            cpg.goto(TARGET_URL,
                                     wait_until="domcontentloaded",
                                     timeout=60000)
                            cpg.wait_for_timeout(3500)
                            try:
                                res = cpg.evaluate(_PAT_PROBE_JS, ws_id)
                            except Exception as e:
                                # Failed to fetch 等瞬时页内错误 -> 重试
                                res = {"status": 0, "code": "eval_failed",
                                       "msg": str(e)[:120]}
                            stt, code = res.get("status"), res.get("code")
                            # 上游原始响应(脱敏)进日志, 供判定排障
                            raw = (res.get("raw") or "")
                            if raw:
                                raw = re.sub(
                                    r'("(?:token|credential|secret'
                                    r'|value)"\s*:\s*")[^"]{6}',
                                    r'\1***', raw, flags=re.I)
                                raw = re.sub(r'sk-[A-Za-z0-9_-]{4,}',
                                             'sk-***', raw)
                                log(f"  {email}: PAT响应 {stt} "
                                    f"{code or '-'} | "
                                    + raw[:300].replace("\n", " "))
                            if code == "no_token":
                                verdict = "窗口未登录"
                                break
                            verdict = _pat_verdict(stt, code)
                            if verdict == "good_created":
                                # 真建出来了 —— 删掉不留痕
                                tk = cpg.evaluate(_WS_TOKEN_JS, ws_id)
                                if res.get("cred") and tk:
                                    cpg.evaluate(_PAT_DELETE_JS, {
                                        "ws": ws_id,
                                        "cid": res["cred"],
                                        "tok": tk})
                                verdict = "good"
                                break
                            if verdict:
                                break
                            # token_expired 等未知 → 再刷一次重试
                            log(f"  {email}: 第{retry+1}次 "
                                f"{stt}/{code}, 刷新重试")
                        if not verdict:
                            verdict = f"unknown:{stt}/{code}"
                            log(f"✗ {email}: 未知响应 {stt} "
                                f"{code} {(res.get('msg') or '')[:80]}")
                        a["pat"] = verdict
                        a["pat_at"] = _now()
                        a["ws_id"] = ws_id
                        _ws_list_add(
                            a, ws_id,
                            st.get("mother_workspace_name")
                            or "", "standard-user")
                        # 能探到 verdict = 号存在且窗口已登录
                        # = 注册已成功, 回填 reg
                        if verdict != "窗口未登录" \
                                and not a.get("reg"):
                            a["reg"] = "yes"
                            a["reg_at"] = a.get("reg_at") or _now()
                        PAT_JOB["results"][aid] = verdict
                        tag = {"good": "✓ 良好", "low": "✗ 低级"}\
                            .get(verdict, "? " + verdict)
                        log(f"{tag} {email}")
                    finally:
                        try:
                            cbr.close()
                        except Exception:
                            pass
                except Exception as e:
                    PAT_JOB["results"][aid] = str(e)[:120]
                    log(f"✗ {email}: {str(e)[:120]}")
                finally:
                    accs_all = _load_accounts()
                    for x in accs_all:
                        if x["id"] == aid:
                            x.clear(); x.update(a)
                            break
                    _save_accounts(accs_all)
            try:
                mbr.close()
            except Exception:
                pass
    finally:
        PAT_JOB["running"] = False
        log("—— PAT 检验结束 ——"
            + (" (手动停止)" if PAT_JOB["stop"] else ""))


# ---------------- 加入空间任务 ----------------
JOIN_JOB = {"running": False, "log": [], "results": {},
            "stop": False}


def _join_worker(ids, mname, seat="prolite"):
    """空间母号批量邀请 → 子号开窗刷新 → 接受邀请 → 记 space 字段。
    与 PAT 流程前半段相同, 但收尾不建 PAT, 只落成员身份。
    seat: default(标准) | prolite(高级) —— codex(usage_based)
    空间会被强制改回 usage_based。"""
    JOIN_JOB["running"] = True
    JOIN_JOB["stop"] = False
    JOIN_JOB["log"] = []
    JOIN_JOB["results"] = {}

    def log(m):
        line = "%s %s" % (time.strftime("%H:%M:%S"), m)
        JOIN_JOB["log"].append(line)

    from playwright.sync_api import sync_playwright
    try:
        ms = _load_mothers()
        pat = (_settings().get("mother_window") or "").strip()
        m = next((x for x in ms
                  if x["name"] == mname and x["name"] != pat), None)
        if not m:
            log("✗ 空间母号 %s 不在列表 —— 先到空间母号页导入"
                " (Pat测试母号不参与此功能)" % mname)
            for i in ids:
                JOIN_JOB["results"][i] = "母号不存在"
            return
        # 目标空间: 存过的直接用; 没存就连母号拉 owner 空间存上
        ws_id = (m.get("ws") or "").strip()
        if not ws_id:
            memail, wss, werr = _list_workspaces(mname)
            if werr:
                log("✗ 拉母号空间失败: " + werr)
                for i in ids:
                    JOIN_JOB["results"][i] = "母号: " + werr
                return
            own = next((w for w in wss
                        if w.get("role") == "account-owner"),
                       None) or (wss[0] if wss else None)
            if not own:
                log("✗ 母号没有任何空间")
                for i in ids:
                    JOIN_JOB["results"][i] = "母号无空间"
                return
            ws_id = own["id"]
            m["ws"] = ws_id
            m["ws_name"] = own.get("name") or ""
            _save_mothers(ms)
            log("母号空间自动选择: %s (%s)"
                % (m["ws_name"], ws_id[:8]))
        ws_name = m.get("ws_name") or ws_id[:8]
        mws, err = _mother_open(mname)
        if err:
            log("✗ 母号窗口: " + err)
            for i in ids:
                JOIN_JOB["results"][i] = "母号: " + err
            return
        log("母号窗口 %s 已连, 目标空间 %s (%s), 席位 %s"
            % (mname, ws_name, ws_id[:8], seat))
        with sync_playwright() as pw:
            mbr = pw.chromium.connect_over_cdp(mws)
            mpg = _find_cgpt_page(mbr)
            if not mpg:
                mpg = mbr.contexts[0].new_page()
                mpg.goto(TARGET_URL,
                         wait_until="domcontentloaded", timeout=60000)
                mpg.wait_for_timeout(4000)
            # 母号批量邀请 —— 一次请求
            emails = {}
            for aid in ids:
                a = next((x for x in _load_accounts()
                          if x["id"] == aid), None)
                if a:
                    emails[aid] = a["email"]
            r = {}
            for att in range(3):
                try:
                    r = mpg.evaluate(_INVITE_JS, {
                        "ws": ws_id,
                        "emails": list(emails.values()),
                        "fid": str(uuid.uuid4()),
                        "sid": str(uuid.uuid4()),
                        "seat": seat})
                except Exception as e:
                    r = {"status": 0, "body": str(e)[:120]}
                if r.get("status") in (0, 401) \
                        or "token_expired" in (r.get("body") or ""):
                    log("  邀请请求异常(%s), 刷新页面重试 (%d/3)"
                        % (r.get("status"), att + 1))
                    try:
                        mpg.goto(TARGET_URL,
                                 wait_until="domcontentloaded",
                                 timeout=60000)
                        mpg.wait_for_timeout(4000)
                    except Exception:
                        pass
                    continue
                break
            if r.get("status") != 200:
                log("✗ 批量邀请失败 %s %s"
                    % (r.get("status"), (r.get("body") or "")[:150]))
                for i2 in ids:
                    JOIN_JOB["results"][i2] = "邀请失败"
                return
            try:
                bj = json.loads(r.get("body") or "{}")
            except Exception:
                bj = {}
            already = set(bj.get("already_member_emails") or [])
            # 新发邀请的 email → invite_id, 给子号协议接受用
            iid_by_email = {}
            for iv in (bj.get("account_invites") or []):
                if iv.get("email_address") and iv.get("id"):
                    iid_by_email[iv["email_address"]] = iv["id"]
            log("→ 批量邀请完成: 新发 %d 个, 已是成员 %d 个"
                % (len(emails) - len(already & set(emails.values())),
                   len(already & set(emails.values()))))
            joined = 0

            def _mark_joined(a, wsn, wsd, how):
                a["space"] = wsn
                a["space_ws"] = wsd
                a["space_mother"] = mname
                a["space_seat"] = r.get("seat") or seat
                a["space_at"] = _now()
                a.pop("space_left", None)
                _ws_list_add(a, wsd, wsn, "standard-user")
                JOIN_JOB["results"][a["id"]] = \
                    "已入 %s (%s)%s" % (wsn, wsd[:8],
                                     " [协议]" if how == "p" else "")

            # 逐个子号: 协议接受优先(ios.at), 无 at/失败再开窗
            for aid in ids:
                if JOIN_JOB["stop"]:
                    log("⏹ 已手动停止")
                    break
                a = next((x for x in _load_accounts()
                          if x["id"] == aid), None)
                if not a:
                    continue
                email = a["email"]
                try:
                    if email in already:
                        # API 权威判定已是成员 —— 免开窗直接落位,
                        # 开窗接邀请只对"新发的邀请"有意义
                        joined += 1
                        _mark_joined(a, ws_name, ws_id, "w")
                        JOIN_JOB["results"][aid] = \
                            "已是成员 %s (%s)" % (ws_name, ws_id[:8])
                        log("✓ %s: 已是成员, 直接落位" % email)
                        continue
                    px = _load_proxies()
                    p = next((x for x in px
                              if x["id"] == a.get("proxy_id")), None)
                    if not p or p.get("banned"):
                        p = _pick_proxy(px, email)
                        if not p:
                            cool = (" (冷却中 %d 条)"
                                    % PICK_LAST["cooled"]
                                    if PICK_LAST["cooled"] else "")
                            JOIN_JOB["results"][aid] = \
                                "没有可用代理" + cool
                            log("✗ %s: 没有可用代理%s"
                                % (email, cool))
                            continue
                        _bind_proxy(p, email)
                        a["proxy_id"] = p["id"]
                        _save_proxies(px)
                    # 协议路径: ios.at + 邀请响应里的 invite_id
                    iid = iid_by_email.get(email)
                    if iid and (a.get("ios") or {}).get("at"):
                        ok, code, detail = _proto_accept_invite(
                            a, p, ws_id, iid)
                        verified = False
                        if ok:
                            # 假成功防护: 母号复邀 —— 已落成员会进
                            # already_member_emails。落成员有约10s
                            # 传播延迟, 轮3次再判空炮
                            for _vi in range(3):
                                if _vi:
                                    time.sleep(8)
                                try:
                                    rv = mpg.evaluate(_INVITE_JS, {
                                        "ws": ws_id,
                                        "emails": [email],
                                        "fid": str(uuid.uuid4()),
                                        "sid": str(uuid.uuid4()),
                                        "seat": seat})
                                    bj2 = json.loads(
                                        rv.get("body") or "{}")
                                    verified = email in set(
                                        bj2.get(
                                            "already_member_emails")
                                        or [])
                                except Exception:
                                    verified = False
                                if verified:
                                    break
                            if not verified:
                                log("  %s: accept 200 但复邀3次"
                                    "未确认成员 (假成功), 转开窗"
                                    % email)
                        if ok and verified:
                            joined += 1
                            _mark_joined(a, ws_name, ws_id, "p")
                            log("✓ %s: 协议接邀请已入 %s (%s)"
                                % (email, ws_name, ws_id[:8]))
                            continue
                        if code in ("at_expired", "no_at", "no_pid"):
                            log("  %s: 协议接不可用(%s), "
                                "转开窗" % (email, code))
                        elif not ok:
                            log("  %s: 协议接失败 %s %s, 转开窗"
                                % (email, code, detail[:80]))
                    elif iid:
                        pass  # 无 ios.at 直接走开窗
                    else:
                        log("  %s: 邀请响应里没找到 "
                            "invite_id, 走开窗碰运气" % email)
                    dir_id, cws, err = _roxy_open_for(email, p)
                    if err or not cws:
                        JOIN_JOB["results"][aid] = "开窗: " + (err or "")
                        log("✗ %s: 开窗失败 %s" % (email, err))
                        continue
                    a["win"] = dir_id
                    cbr = pw.chromium.connect_over_cdp(cws)
                    try:
                        cpg = _find_cgpt_page(cbr)
                        if not cpg:
                            cpg = cbr.contexts[0].new_page()
                        done = None
                        for att in range(3):
                            cpg.goto(TARGET_URL,
                                     wait_until="domcontentloaded",
                                     timeout=60000)
                            cpg.wait_for_timeout(3500)
                            try:
                                res = cpg.evaluate(
                                    _ACCEPT_INVITE_JS, ws_id)
                            except Exception as e:
                                res = {"ok": False,
                                       "tried":
                                       ["eval:" + str(e)[:60]]}
                            if res.get("code") == "no_token":
                                done = "窗口未登录"
                                break
                            if res.get("ok"):
                                done = "ok"
                                break
                            # API 没找到邀请 → UI 兜底找接受按钮
                            clicked = False
                            for sel in (
                                    'button:has-text("Accept")',
                                    'button:has-text("加入")',
                                    'button:has-text("接受")',
                                    '[data-testid*="accept"]'):
                                try:
                                    b = cpg.query_selector(sel)
                                    if b and b.is_visible():
                                        b.click()
                                        clicked = True
                                        log("  %s: 点了界面接受按钮"
                                            % email)
                                        cpg.wait_for_timeout(2500)
                                        break
                                except Exception:
                                    pass
                            # 每轮成员校验: 邀请可能免点已自动入队
                            try:
                                mc = cpg.evaluate(
                                    _MEMBER_CHECK_JS, ws_id)
                            except Exception:
                                mc = {}
                            if mc.get("found") and "invited" \
                                    not in (mc.get("role") or ""):
                                done = "ok"
                                break
                            if clicked:
                                continue   # 点了按钮, 下轮再校验
                            if att < 2:
                                log("  %s: 第%d次没找到邀请,"
                                    " 3s后重刷" % (email, att + 1))
                                time.sleep(3)
                                continue
                            done = "没找到邀请 (%s)" % ",".join(
                                res.get("tried") or [])[:80]
                        if done == "ok":
                            joined += 1
                            _mark_joined(a, ws_name, ws_id, "w")
                            log("✓ %s: 已入 %s (%s)"
                                % (email, ws_name, ws_id[:8]))
                        else:
                            JOIN_JOB["results"][aid] = \
                                done or "点了接受但未确认入队"
                            log("✗ %s: %s" % (email, done
                                            or "点了接受但未确认入队"))
                    finally:
                        try:
                            cbr.close()
                        except Exception:
                            pass
                except Exception as e:
                    JOIN_JOB["results"][aid] = str(e)[:120]
                    log("✗ %s: %s" % (email, str(e)[:120]))
                finally:
                    accs_all = _load_accounts()
                    for x in accs_all:
                        if x["id"] == aid:
                            x.clear(); x.update(a)
                            break
                    _save_accounts(accs_all)
            try:
                mbr.close()
            except Exception:
                pass
            # 落母号统计: 执行次数 + 累计拉入数
            ms2 = _load_mothers()
            mm = next((x for x in ms2 if x["name"] == mname), None)
            if mm:
                mm["join_runs"] = mm.get("join_runs", 0) + 1
                mm["join_count"] = mm.get("join_count", 0) + joined
                mm["join_at"] = _now()
                _save_mothers(ms2)
                log("→ %s 累计执行 %d 次加入, 拉入 %d 个"
                    % (mname, mm["join_runs"], mm["join_count"]))
    finally:
        JOIN_JOB["running"] = False
        log("—— 加入空间结束 ——"
            + (" (手动停止)" if JOIN_JOB["stop"] else ""))


# ---------------- 退出空间 ----------------
# 子号主动退: 换目标空间的 workspace token ->
#   DELETE /backend-api/accounts/{ws}/users/{自己uid}
# 目标两种给法: pairs={账号id: 空间id} 精准退;
#   或 ws_name=空间名 (空间筛选联动), 按成员列表现查 id
LEAVE_JOB = {"running": False, "log": [], "results": {},
             "stop": False}


def _ws_list_add(a, ws_id, name="", role=""):
    """往 a.ws_list 里补一条成员记录 (按 id 去重, 补缺失字段)。"""
    if not ws_id:
        return
    lst = a.setdefault("ws_list", [])
    for w in lst:
        if w.get("id") == ws_id:
            if name:
                w["name"] = name
            if role:
                w["role"] = role
            return
    lst.append({"id": ws_id, "name": name, "role": role})


def _cf_call(fn, n=4, wait=1.5):
    """执行一次 HTTP 调用; CF 间歇拦 403(HTML挑战页)时同会话重试。
    API 层的 403 是 application/json, 不触发重试。"""
    r = fn()
    for _ in range(n - 1):
        ct = (r.headers.get("content-type") or "")
        if r.status_code != 403 or "json" in ct.lower():
            break
        time.sleep(wait)
        r = fn()
    return r


def _mark_left(a, ws_id, wsn):
    """退出成功后的统一记账。"""
    a["space_left"] = {"ws": ws_id, "name": wsn,
                       "at": _now(), "by": "self"}
    if a.get("space_ws") == ws_id:
        for k in ("space", "space_ws", "space_mother",
                  "space_at", "space_seat"):
            a.pop(k, None)
    if a.get("ws_id") == ws_id:
        a.pop("ws_id", None)
    if a.get("ws_list"):
        a["ws_list"] = [w for w in a["ws_list"]
                        if w.get("id") != ws_id]


def _proto_leave_ws(a, p, ws_id):
    """纯协议退出: ios.at + 账号代理(链式) + chrome指纹, 不开窗。
    返回 (ok, wsn, code, detail)。code: at_expired/not_member/
    sole_owner/HTTP xxx/no_at。"""
    at = (a.get("ios") or {}).get("at")
    if not at:
        return False, "", "no_at", ""
    if (a.get("ios") or {}).get("at_dead"):
        # 退过一次空间后 at 服务端作废, 不再浪费请求
        return False, "", "at_expired", "at_dead"
    from curl_cffi import requests as _cr
    relay = _ChainRelay(p, _upstream())
    try:
        s = _cr.Session(proxy=relay.url(),
                        impersonate="chrome", timeout=40)
        H = {"authorization": "Bearer " + at}
        r = _cf_call(lambda: s.get(
            "https://chatgpt.com/backend-api/accounts"
            "/check/v4-2023-04-27", headers=H))
        if r.status_code == 401:
            return False, "", "at_expired", r.text[:150]
        if r.status_code != 200:
            return False, "", "HTTP %s" % r.status_code, \
                r.text[:150]
        mine, names = None, []
        for v in (r.json().get("accounts") or {}).values():
            x = v.get("account") or {}
            if x.get("structure") != "workspace":
                continue
            names.append(x.get("name") or "")
            if x.get("account_id") == ws_id:
                mine = x
        if not mine:
            return False, "", "not_member", \
                ",".join(n for n in names if n)
        uid = (mine.get("account_user_id")
               or "").split("__")[0]
        hw = dict(H)
        hw["chatgpt-account-id"] = ws_id
        if "owner" in str(
                mine.get("account_user_role") or "").lower():
            oc = _cf_call(lambda: s.get(
                "https://chatgpt.com/backend-api/accounts"
                "/%s/users/owner_count" % ws_id, headers=hw))
            if oc.status_code == 200 and \
                    (oc.json().get("owner_count") or 0) <= 1:
                return False, "", "sole_owner", ""
        # 429 "subscription update in progress" 是瞬时锁, 轮重试
        d = None
        for _try in range(4):
            d = _cf_call(lambda: s.delete(
                "https://chatgpt.com/backend-api/accounts/%s"
                "/users/%s" % (ws_id, uid), headers=hw))
            if d.status_code != 429:
                break
            time.sleep(10)
        if d.status_code == 200:
            # 退出成功后该 at 服务端作废 —— 标记, 后续协议操作
            # (退出/接邀) 全部转窗口
            a.setdefault("ios", {})["at_dead"] = True
            return True, mine.get("name") or "", "", ""
        return False, "", "HTTP %s" % d.status_code, d.text[:150]
    finally:
        relay.close()


def _proto_accept_invite(a, p, ws_id, iid):
    """纯协议接受邀请: ios.at + 账号代理(链式), 不开窗。
    POST /accounts/{pid}/invites/accept  {invite_id} —— 实测成功路径;
    注意 accept 常回 {"success":true} 却空炮 (席位满等), 成员确认
    交给调用方复邀一次看 already_member_emails。
    返回 (ok, code, detail)。code: no_at/at_expired/no_pid/HTTP xxx。"""
    at = (a.get("ios") or {}).get("at")
    if not at:
        return False, "no_at", ""
    if (a.get("ios") or {}).get("at_dead"):
        return False, "at_expired", "at_dead"
    from curl_cffi import requests as _cr
    relay = _ChainRelay(p, _upstream())
    try:
        s = _cr.Session(proxy=relay.url(),
                        impersonate="chrome", timeout=40)
        H = {"authorization": "Bearer " + at,
             "content-type": "application/json"}

        def _check():
            r = _cf_call(lambda: s.get(
                "https://chatgpt.com/backend-api/accounts"
                "/check/v4-2023-04-27", headers=H))
            if r.status_code != 200:
                return r.status_code, None, False
            pid = None
            found = False
            for v in (r.json().get("accounts") or {}).values():
                x = v.get("account") or {}
                if x.get("structure") == "personal":
                    pid = x.get("account_id")
                elif x.get("account_id") == ws_id:
                    found = True
            return 200, pid, found

        code, pid, found = _check()
        if code == 401:
            return False, "at_expired", ""
        if code != 200:
            return False, "HTTP %s" % code, ""
        if found:
            return True, "", ""
        if not pid:
            return False, "no_pid", ""
        h = dict(H)
        h["chatgpt-account-id"] = pid
        ac = _cf_call(lambda: s.post(
            "https://chatgpt.com/backend-api/accounts/%s"
            "/invites/accept" % pid, headers=h,
            json={"invite_id": iid}))
        if ac.status_code == 401:
            return False, "at_expired", ac.text[:150]
        if ac.status_code != 200:
            return False, "HTTP %s" % ac.status_code, \
                ac.text[:150]
        # 注意: 这里的 success 可能是假阳 (席位满等),
        # 成员确认交给调用方再邀一次看 already_member_emails
        return True, "", ""
    finally:
        relay.close()


def _leave_worker(ids, ws_name=None, pairs=None):
    from playwright.sync_api import sync_playwright
    LEAVE_JOB["running"] = True
    LEAVE_JOB["stop"] = False
    LEAVE_JOB["log"] = []
    LEAVE_JOB["results"] = {}

    def log(m):
        LEAVE_JOB["log"].append(
            "%s %s" % (time.strftime("%H:%M:%S"), m))

    log("—— 退出空间开始 ——")
    try:
        with sync_playwright() as pw:
            for aid in ids:
                if LEAVE_JOB["stop"]:
                    log("⏹ 已手动停止")
                    break
                accs = _load_accounts()
                a = next((x for x in accs if x["id"] == aid), None)
                if not a:
                    continue
                email = a["email"]
                try:
                    # 解析目标空间 id —— 只按存量记录
                    # (a.space_ws / a.ws_list), 实况拉取归「查空间」
                    target = (pairs or {}).get(aid)
                    if not target and ws_name:
                        if (a.get("space") or "") == ws_name \
                                and a.get("space_ws"):
                            target = a["space_ws"]
                        if not target:
                            for w in a.get("ws_list") or []:
                                if (w.get("name") or "") \
                                        == ws_name:
                                    target = w.get("id")
                                    break
                    if not target:
                        known = ", ".join(
                            w.get("name")
                            for w in (a.get("ws_list") or [])
                            if w.get("name")) \
                            or (a.get("space") or "无")
                        LEAVE_JOB["results"][aid] = "不在该空间"
                        log("✗ %s: 不在空间 %s (记录在: %s)"
                            " —— 记录过期先「查空间」"
                            % (email, ws_name or "?", known))
                        continue
                    p = next((x for x in _load_proxies()
                              if x["id"] == a.get("proxy_id")), None)
                    if not p or p.get("banned"):
                        LEAVE_JOB["results"][aid] = "没绑代理"
                        log("✗ %s: 没绑代理" % email)
                        continue
                    # —— 纯协议优先: 有 ios.at 就不开窗 ——
                    if (a.get("ios") or {}).get("at"):
                        ok, wsn, code, detail = \
                            _proto_leave_ws(a, p, target)
                        if ok:
                            wsn = wsn or ws_name or target[:8]
                            _mark_left(a, target, wsn)
                            LEAVE_JOB["results"][aid] = \
                                "已退 %s (%s)" % (wsn, target[:8])
                            log("✓ %s: 已退出 %s (%s) [协议]"
                                % (email, wsn, target[:8]))
                            continue
                        if code == "not_member":
                            LEAVE_JOB["results"][aid] = \
                                "不在该空间"
                            log("✗ %s: 不在该空间 (实况: %s)"
                                % (email, detail or "无"))
                            continue
                        if code == "sole_owner":
                            LEAVE_JOB["results"][aid] = \
                                "唯一owner不能退"
                            log("✗ %s: 是该空间唯一 owner,"
                                " 先转交再退" % email)
                            continue
                        if code != "at_expired":
                            LEAVE_JOB["results"][aid] = code
                            log("✗ %s: 协议退出 %s %s"
                                % (email, code, detail))
                            continue
                        log("… %s: ios.at 已过期, 走窗口" % email)
                    dir_id, cws, err = _roxy_open_for(email, p)
                    if err or not cws:
                        LEAVE_JOB["results"][aid] = \
                            "开窗: " + (err or "")
                        log("✗ %s: 开窗失败 %s" % (email, err))
                        continue
                    a["win"] = dir_id
                    cbr = pw.chromium.connect_over_cdp(cws)
                    try:
                        cpg = _find_cgpt_page(cbr)
                        if not cpg:
                            cpg = cbr.contexts[0].new_page()
                            cpg.goto(TARGET_URL,
                                     wait_until="domcontentloaded",
                                     timeout=60000)
                            cpg.wait_for_timeout(3000)
                        r = cpg.evaluate(_LEAVE_WS_JS, target)
                        code = r.get("code")
                        if r.get("status") == 200:
                            wsn = r.get("name") \
                                or ws_name or target[:8]
                            _mark_left(a, target, wsn)
                            LEAVE_JOB["results"][aid] = \
                                "已退 %s (%s)" % (wsn, target[:8])
                            log("✓ %s: 已退出 %s (%s)"
                                % (email, wsn, target[:8]))
                        elif code == "no_token":
                            LEAVE_JOB["results"][aid] = "窗口未登录"
                            log("✗ %s: 窗口未登录" % email)
                        elif code == "not_member":
                            names = ", ".join(
                                w.get("name")
                                for w in r.get("list") or [])
                            LEAVE_JOB["results"][aid] = \
                                "不在该空间"
                            log("✗ %s: 不在该空间 (实际在: %s)"
                                % (email, names or "无"))
                        elif code == "sole_owner":
                            LEAVE_JOB["results"][aid] = \
                                "唯一owner不能退"
                            log("✗ %s: 是该空间唯一 owner,"
                                " 先转交再退" % email)
                        else:
                            LEAVE_JOB["results"][aid] = \
                                "HTTP %s" % r.get("status")
                            log("✗ %s: HTTP %s %s"
                                % (email, r.get("status"),
                                   (r.get("body") or "")[:120]))
                    finally:
                        try:
                            cbr.close()
                        except Exception:
                            pass
                except Exception as e:
                    LEAVE_JOB["results"][aid] = str(e)[:120]
                    log("✗ %s: %s" % (email, str(e)[:120]))
                finally:
                    accs_all = _load_accounts()
                    for x in accs_all:
                        if x["id"] == aid:
                            x.clear(); x.update(a)
                            break
                    _save_accounts(accs_all)
    finally:
        LEAVE_JOB["running"] = False
        log("—— 退出空间结束 ——"
            + (" (手动停止)" if LEAVE_JOB["stop"] else ""))


def _roxy_close_window(dir_id):
    """只关浏览器进程 —— 窗口配置留着 (不删, 下次 open 秒起)。"""
    cfg = _roxy_cfg()
    return _roxy_call("/browser/close",
                      {"workspaceId": cfg["workspace_id"],
                       "dirId": dir_id}, timeout=30).get("error")


def _roxy_delete_window(dir_id):
    """关+删一个 Roxy 窗口 (先 close 再 delete, dirIds 是数组)。
    返回 err|None —— 尽力而为, 调用方不因此中断。"""
    cfg = _roxy_cfg()
    _roxy_close_window(dir_id)
    r = _roxy_call("/browser/delete",
                   {"workspaceId": cfg["workspace_id"],
                    "dirIds": [dir_id]}, timeout=30)
    err = r.get("error")
    if err and "不存在" in err:
        return None          # 已经没了 = 目标达成, 不算失败
    return err


# ---------------- CPA 号池 (CLIProxyAPI) ----------------
def _cpa_call(method, path, body=None, timeout=15, st=None):
    """调 CPA 管理接口, 返回 (status, json|None, err)。
    需要设置页已配 cpa_url (+cpa_key)。
    st 缺省用 GPT settings; G 侧传 _gsettings()。"""
    s = st or _settings()
    base = (s.get("cpa_url") or "").strip().rstrip("/")
    if not base:
        return 0, None, "未配置 CPA 地址 (设置页)"
    if "://" not in base:
        base = "http://" + base
    key = (s.get("cpa_key") or "").strip()
    hdrs = {"Authorization": "Bearer " + key} if key else {}
    url = base + path
    up = _upstream_of(s) if url.startswith("https://") else None
    try:
        if method.upper() == "GET":
            st, b = _https_status_get(url, up, timeout,
                                      headers=hdrs)
        else:
            st, b = _http_post_json(url, body or {},
                                    headers=hdrs, upstream=up,
                                    timeout=timeout,
                                    method=method.upper())
    except Exception as e:
        return 0, None, str(e)[:160]
    try:
        j = json.loads(b) if b else None
    except Exception:
        j = None
    if st in (401, 403):
        return st, j, "管理 Key 无效 (%d)" % st
    if st >= 400:
        return st, j, "HTTP %d: %s" % (
            st, (b or b"")[:160].decode(errors="ignore"))
    return st, j, None


def _cpa_list_creds():
    """池内凭证列表 (v8 credentials / v0 auth-files)。"""
    st, j, err = _cpa_call("GET", "/v8/management/credentials")
    if st == 404:
        st, j, err = _cpa_call("GET", "/v0/management/auth-files")
    return j, err


def _cpa_test(url, key, up):
    """CPA 连通测试 → dict 结果 (v8 credentials, 降级 v0 api-keys)。"""
    url = (url or "").strip().rstrip("/")
    if not url:
        return {"error": "先填 CPA 地址"}
    if "://" not in url:
        url = "http://" + url
    hdrs = {"Authorization": "Bearer " + key} if key else None
    t0 = time.time()
    try:
        st, body = _https_status_get(
            url + "/v8/management/credentials", up, 12, headers=hdrs)
        ver = "v8"
        if st == 404:
            st, body = _https_status_get(
                url + "/v0/management/api-keys", up, 12, headers=hdrs)
            ver = "v0"
        ms = int((time.time() - t0) * 1000)
        if st in (401, 403):
            return {"error": f"管理 Key 无效或未授权 ({st})", "ms": ms}
        if st != 200:
            return {"error": f"HTTP {st}: "
                             f"{body[:160].decode(errors='ignore')}",
                    "ms": ms}
        try:
            j = json.loads(body)
        except Exception:
            j = None
        n = None
        if isinstance(j, list):
            n = len(j)
        elif isinstance(j, dict):
            for kk in ("credentials", "items", "files",
                       "api-keys", "api_keys", "data"):
                if isinstance(j.get(kk), list):
                    n = len(j[kk])
                    break
        return {"ok": True, "ms": ms, "ver": ver, "creds": n}
    except Exception as e:
        return {"error": str(e)[:200]}


def _cpa_push_cred(name, cred, st=None):
    """推凭证 JSON 入 CPA 池 (v8/v0 auth-files?name=, 原始 JSON body)。
    返回 err|None。st 缺省 GPT settings; G 侧传 _gsettings()。"""
    q = "?name=" + urllib.parse.quote(name)
    st_, j, err = _cpa_call(
        "POST", "/v8/management/auth-files" + q, cred,
        timeout=30, st=st)
    if st_ == 404:
        st_, j, err = _cpa_call(
            "POST", "/v0/management/auth-files" + q, cred,
            timeout=30, st=st)
    return err


# ---------------- Codex OAuth 本地实现 ----------------
# 照 CLIProxyAPI internal/auth/codex 源码: PKCE → auth.openai.com
# 授权 → 回调 code → 经账号代理换 token → CPA 凭证 JSON。
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_AUTH_URL = "https://auth.openai.com/oauth/authorize"
OAUTH_TOKEN_HOST = "auth.openai.com"
OAUTH_TOKEN_PATH = "/oauth/token"
OAUTH_REDIRECT = "http://localhost:1455/auth/callback"


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _oauth_gen():
    """本地算 PKCE + state → (auth_url, state, code_verifier)。
    不依赖 CPA —— 链接参数照 CPA 源码一模一样。"""
    verifier = _b64u(secrets.token_bytes(96))
    challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
    state = secrets.token_hex(16)
    q = urllib.parse.urlencode({
        "client_id": OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": OAUTH_REDIRECT,
        "scope": "openid email profile offline_access",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true"})
    return OAUTH_AUTH_URL + "?" + q, state, verifier


def _jwt_claims(tok):
    """解 JWT payload (不验签)。返回 claims dict。"""
    try:
        pl = (tok or "").split(".")[1]
        pl += "=" * (-len(pl) % 4)
        return json.loads(base64.urlsafe_b64decode(pl))
    except Exception:
        return {}


def _req_via(p, method, host, path, headers=None, body=b"",
             timeout=30, up=_UNSET):
    """经账号代理 p 发任意 HTTP 请求 → https://host/path。
    链式: 本机→上级代理→账号代理→目标 —— 与注册/授权同 IP。
    返回 (status, body)。"""
    s = _dial_via_account_proxy(p, host, 443, timeout, up)
    s = ssl.create_default_context().wrap_socket(
        s, server_hostname=host)
    s.settimeout(timeout)
    try:
        h = {"Host": host, "Connection": "close",
             "Content-Length": str(len(body))}
        h.update(headers or {})
        raw = ("%s %s HTTP/1.1\r\n%s\r\n"
               % (method, path,
                  "".join("%s: %s\r\n" % kv for kv in h.items()))
               ).encode() + body
        s.sendall(raw)
        buf = b""
        while True:
            ch = s.recv(8192)
            if not ch:
                break
            buf += ch
    finally:
        try:
            s.close()
        except Exception:
            pass
    head, _, body = buf.partition(b"\r\n\r\n")
    st = int(head.split(b" ", 2)[1]) if b" " in head else 0
    if b"chunked" in head.lower():
        out, rest = b"", body
        while True:
            nl = rest.find(b"\r\n")
            if nl < 0:
                break
            try:
                n = int(rest[:nl].split(b";")[0].strip(), 16)
            except ValueError:
                break
            if n == 0:
                break
            out += rest[nl + 2: nl + 2 + n]
            rest = rest[nl + 2 + n + 2:]
        body = out
    return st, body


def _post_form_via(p, host, path, form, timeout=30, up=_UNSET):
    """经账号代理 p 发 x-www-form-urlencoded POST (token 交换用)。"""
    return _req_via(p, "POST", host, path,
                    {"Content-Type":
                     "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
                    form, timeout, up)


def _oauth_exchange(p, code, verifier):
    """经账号代理用 code 换 token。返回 (token_resp dict, err)。"""
    form = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "client_id": OAUTH_CLIENT_ID,
        "code": code,
        "redirect_uri": OAUTH_REDIRECT,
        "code_verifier": verifier}).encode()
    try:
        st, body = _post_form_via(p, OAUTH_TOKEN_HOST,
                                  OAUTH_TOKEN_PATH, form)
    except Exception as e:
        return None, str(e)[:160]
    try:
        j = json.loads(body) if body else {}
    except Exception:
        j = {}
    if st != 200:
        return None, "token 交换 HTTP %d: %s" % (
            st, (body or b"")[:160].decode(errors="ignore"))
    if not j.get("access_token"):
        return None, "响应里没有 access_token"
    return j, None


def _oauth_cred(j, proxy_url):
    """token 响应 → CPA codex 凭证 JSON (字段照 CodexTokenStorage,
    带 proxy_url —— 池子消费凭证时继续走同一 IP)。"""
    idt = j.get("id_token") or ""
    cl = _jwt_claims(idt)
    auth = cl.get("https://api.openai.com/auth") or {}
    now = time.time()
    exp = now + int(j.get("expires_in") or 0)
    rfc = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                  time.gmtime(t))
    return {
        "id_token": idt,
        "access_token": j.get("access_token") or "",
        "refresh_token": j.get("refresh_token") or "",
        "account_id": auth.get("chatgpt_account_id") or "",
        "last_refresh": rfc(now),
        "email": cl.get("email") or "",
        "type": "codex",
        "expired": rfc(exp),
        "plan_type": auth.get("chatgpt_plan_type") or "free",
        "proxy_url": proxy_url,
    }


def _cred_name(cred):
    """codex-<8hex>-<email>-<plan>.json (照 CPA 池内命名风格)。"""
    em = (cred.get("email") or "unknown").strip()
    plan = (cred.get("plan_type") or "free").strip()
    return "codex-%s-%s-%s.json" % (
        secrets.token_hex(4), em, plan)


CPA_JOB = {"running": False, "log": [], "results": {},
           "stop": False}


def _oauth_ttl_s():
    """授权链接/回调码有效期 —— 超时就当死了, 不再等。"""
    try:
        return max(60, int(float(
            _settings().get("oauth_ttl_min") or 10) * 60))
    except Exception:
        return 600


def _oauth_expire(accs):
    """惰性清理: cpa=pending 且 oauth_at 超 TTL → cpa=expired,
    oauth_* 字段清掉 (授权码早死了, 留着没意义)。返回是否有改动。"""
    cut = time.strftime("%Y-%m-%dT%H:%M:%S",
                        time.localtime(time.time() - _oauth_ttl_s()))
    changed = False
    for a in accs:
        if a.get("cpa") == "pending" \
                and (not a.get("oauth_at") or a["oauth_at"] < cut):
            a["cpa"] = "expired"
            for k in ("oauth_url", "oauth_state",
                      "oauth_verifier", "oauth_at"):
                a.pop(k, None)
            changed = True
    if changed:
        _save_accounts(accs)
    return changed


def _cpa_worker(ids):
    """逐账号本地 OAuth: 算链接 → 开(原/同IP新)子号窗口走授权
    → 截 localhost:1455 回调 → 经账号代理换 token
    → 生成带 proxy_url 的 CPA 凭证 JSON 存账号 (a.cpa=ready)。"""
    CPA_JOB["running"] = True
    CPA_JOB["stop"] = False
    CPA_JOB["log"] = []
    CPA_JOB["results"] = {}

    def log(m):
        CPA_JOB["log"].append(
            "%s %s" % (time.strftime("%H:%M:%S"), m))

    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as pw:
            for aid in ids:
                if CPA_JOB["stop"]:
                    log("⏹ 已手动停止")
                    break
                a = next((x for x in _load_accounts()
                          if x["id"] == aid), None)
                if not a or a.get("archived"):
                    continue
                email = a["email"]
                try:
                    px = _load_proxies()
                    p = next((x for x in px
                              if x["id"] == a.get("proxy_id")),
                             None)
                    if not p:
                        CPA_JOB["results"][aid] = "账号没绑代理"
                        log("✗ %s: 没绑代理, 全链同IP做不到" % email)
                        continue
                    # 1) 本地算 OAuth 链接 (不依赖 CPA)
                    url, state, verifier = _oauth_gen()
                    a["oauth_state"] = state
                    a["oauth_url"] = url
                    a["oauth_verifier"] = verifier
                    a["oauth_at"] = _now()
                    log("→ %s: OAuth 链接已生成 (%d分钟时效)"
                        % (email, _oauth_ttl_s() // 60))
                    # 2) 开窗口: 优先复用原来的窗 (win 还在直接连),
                    #    没有就按绑定的同一代理新建 —— IP 不变
                    dir_id, cws, err = _roxy_open_for(email, p)
                    if err or not cws:
                        CPA_JOB["results"][aid] = "开窗: " + (err or "")
                        log("✗ %s: 开窗失败 %s" % (email, err))
                        continue
                    a["win"] = dir_id
                    cbr = pw.chromium.connect_over_cdp(cws)
                    try:
                        # 授权链接开新标签页 —— 不覆盖原有标签
                        cpg = cbr.contexts[0].new_page()
                        _gpt_inject_helper(cpg, a)
                        cpg.goto(url, wait_until="domcontentloaded",
                                 timeout=60000)
                        try:
                            cpg.bring_to_front()
                        except Exception:
                            pass
                        code = None
                        hit = {"u": None}

                        def _take(u):
                            """URL 是 localhost:1455 回调且 state 匹配
                            → 记 code。request 事件/轮询/历史三路共用。"""
                            if not u or not u.startswith(
                                    "http://localhost:1455/"):
                                return
                            qs = urllib.parse.parse_qs(
                                urllib.parse.urlparse(u).query)
                            got = (qs.get("state") or [""])[0]
                            if got and got != state:
                                return
                            if qs.get("code"):
                                hit["u"] = u

                        # 主路: 请求发出瞬间捕获 (跳转 localhost 会
                        # 连接失败成 chrome-error 页, page.url 被顶掉
                        # —— 光靠轮询 url 永远看不到 code)
                        cpg.on("request", lambda r: _take(r.url))
                        cpg.on("requestfailed",
                               lambda r: _take(r.url))
                        cdp = cpg.context.new_cdp_session(cpg)
                        deadline = time.time() + _oauth_ttl_s()
                        while time.time() < deadline:
                            if CPA_JOB["stop"]:
                                break
                            if hit["u"]:
                                qs = urllib.parse.parse_qs(
                                    urllib.parse.urlparse(
                                        hit["u"]).query)
                                code = (qs.get("code")
                                        or [None])[0]
                                break
                            _take(cpg.url or "")
                            # 兜底: chrome-error 页时 url 已丢,
                            # 翻导航历史找那条 localhost 回调
                            try:
                                for e in (cdp.send(
                                        "Page.getNavigationHistory")
                                        .get("entries") or []):
                                    _take(e.get("url"))
                            except Exception:
                                pass
                            if hit["u"]:
                                continue
                            # 有授权按钮就点 (尽力而为)
                            for sel in (
                                    'button:has-text("Authorize")',
                                    'button:has-text("Allow")',
                                    'button:has-text("Continue")',
                                    'button:has-text("授权")',
                                    'button:has-text("允许")',
                                    'button[type="submit"]'):
                                try:
                                    b = cpg.query_selector(sel)
                                    if b and b.is_visible():
                                        b.click()
                                        log("  %s: 点了授权按钮 %s"
                                            % (email, sel))
                                        cpg.wait_for_timeout(1500)
                                        break
                                except Exception:
                                    pass
                            cpg.wait_for_timeout(2000)
                        if not code:
                            if CPA_JOB["stop"]:
                                # 手动停: 链接还在时效内, 留 pending 可手动兜底
                                a["cpa"] = "pending"
                                done = "手动停止"
                            else:
                                # 超时: 链接/码已死, 标过期清字段
                                a["cpa"] = "expired"
                                for k in ("oauth_url", "oauth_state",
                                          "oauth_verifier", "oauth_at"):
                                    a.pop(k, None)
                                done = "授权超时 (链接已过时效)"
                            CPA_JOB["results"][aid] = done
                            log("✗ %s: %s%s" % (email, done,
                                ", 授权页留在窗口里" if CPA_JOB["stop"]
                                else ", 重跑OAuth授权"))
                            continue
                        log("  %s: 回调已截获, 走账号代理换 token"
                            % email)
                        # 3) 同 IP 换 token
                        j, err = _oauth_exchange(p, code, verifier)
                        if err:
                            a["cpa"] = "pending"
                            CPA_JOB["results"][aid] = "换token: " + err
                            log("✗ %s: %s" % (email, err))
                            continue
                        # 4) 组 CPA 凭证 JSON (proxy_url=账号代理)
                        cred = _oauth_cred(
                            j, _proxy_url(p, "url"))
                        a["cred"] = cred
                        a["cred_file"] = _cred_name(cred)
                        a["cred_at"] = _now()
                        a["cpa"] = "ready"
                        a.pop("oauth_url", None)
                        a.pop("oauth_state", None)
                        a.pop("oauth_verifier", None)
                        a.pop("oauth_at", None)
                        CPA_JOB["results"][aid] = "凭证已生成"
                        log("✓ %s: rt/at 到手, 凭证 %s 已备好"
                            % (email, a["cred_file"]))
                        # 设置开了自动推 → 直接入 CPA 池,
                        # 失败留 ready 态可手动推
                        if _settings().get("cpa_autopush", True):
                            err2 = _cpa_push_cred(
                                a["cred_file"], cred)
                            if err2:
                                log("  ⚠ %s: 自动推入池失败 %s"
                                    " —— 凭证在, 可手动推"
                                    % (email, err2))
                            else:
                                a["cpa"] = "yes"
                                a["cpa_at"] = _now()
                                CPA_JOB["results"][aid] = \
                                    "凭证已生成+已入池"
                                log("  ✓ %s: 已自动推入 CPA 池"
                                    % email)
                    finally:
                        try:
                            cbr.close()
                        except Exception:
                            pass
                except Exception as e:
                    CPA_JOB["results"][aid] = str(e)[:120]
                    log("✗ %s: %s" % (email, str(e)[:120]))
                finally:
                    accs_all = _load_accounts()
                    for x in accs_all:
                        if x["id"] == aid:
                            x.clear(); x.update(a)
                            break
                    _save_accounts(accs_all)
    finally:
        CPA_JOB["running"] = False
        log("—— OAuth 授权结束 ——"
            + (" (手动停止)" if CPA_JOB["stop"] else ""))


# ---------------- Google 账号 (antigravity) ----------------
GACCOUNTS_FILE = os.path.join(BASE_DIR, "gaccounts.json")
_gacct_lock = threading.Lock()


def _load_gaccounts():
    try:
        return json.load(open(GACCOUNTS_FILE)).get("accounts") or []
    except Exception:
        return []


def _save_gaccounts(accs):
    with _gacct_lock:
        tmp = GACCOUNTS_FILE + ".tmp"
        json.dump({"accounts": accs}, open(tmp, "w"),
                  ensure_ascii=False, indent=1)
        os.replace(tmp, GACCOUNTS_FILE)


def _new_gaccount(**kw):
    """照 _new_account, id 前缀 gc_ —— 与 GPT 账号区分命名空间。"""
    d = _new_account(**kw)
    d["id"] = "gc_" + uuid.uuid4().hex[:10]
    return d


# OAuth 参数照 CLIProxyAPI internal/auth/antigravity 源码:
# 非PKCE(用 client_secret), 回调 http://localhost:51121/oauth-callback
GOAUTH_CLIENT_ID = ("1071006060591-tmhssin2h21lcre235vtolojh4g403ep"
                    ".apps.googleusercontent.com")
GOAUTH_CLIENT_SECRET = "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"
GOAUTH_REDIRECT = "http://localhost:51121/oauth-callback"
GOAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOAUTH_TOKEN_HOST = "oauth2.googleapis.com"
GOAUTH_SCOPES = " ".join([
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs"])
GOOGLE_USERINFO_HOST = "www.googleapis.com"
GCODE_HOST = "cloudcode-pa.googleapis.com"
GCODE_UA = "google-api-nodejs-client/9.15.1"
GCODE_API_CLIENT = "google-cloud-sdk vscode_cloudshelleditor/0.1"
GCODE_META = ('{"ideType":"IDE_UNSPECIFIED",'
              '"platform":"PLATFORM_UNSPECIFIED",'
              '"pluginType":"GEMINI"}')
GCODE_META_ONBOARD = ('{"ideType":"ANTIGRAVITY",'
                      '"platform":"PLATFORM_UNSPECIFIED",'
                      '"pluginType":"GEMINI"}')


def _goauth_gen():
    """生成 Google OAuth 链接 + state (无 PKCE —— 授权码+secret 换 token)。"""
    state = secrets.token_hex(16)
    q = urllib.parse.urlencode({
        "access_type": "offline",
        "client_id": GOAUTH_CLIENT_ID,
        "prompt": "consent",
        "redirect_uri": GOAUTH_REDIRECT,
        "response_type": "code",
        "scope": GOAUTH_SCOPES,
        "state": state})
    return GOAUTH_AUTH_URL + "?" + q, state


def _goauth_exchange(p, code):
    """经账号代理 code→token。返回 (token dict, err)。"""
    form = urllib.parse.urlencode({
        "code": code,
        "client_id": GOAUTH_CLIENT_ID,
        "client_secret": GOAUTH_CLIENT_SECRET,
        "redirect_uri": GOAUTH_REDIRECT,
        "grant_type": "authorization_code"}).encode()
    try:
        st, body = _post_form_via(p, GOAUTH_TOKEN_HOST, "/token",
                                  form, up=_gupstream())
    except Exception as e:
        return None, str(e)[:160]
    try:
        j = json.loads(body) if body else {}
    except Exception:
        j = {}
    if st != 200:
        return None, "token 交换 HTTP %d: %s" % (
            st, (body or b"")[:200].decode(errors="ignore"))
    if not j.get("access_token"):
        return None, "响应里没有 access_token"
    return j, None


def _g_userinfo(p, at):
    """经账号代理拿 Google userinfo → email|None。"""
    try:
        st, body = _req_via(
            p, "GET", GOOGLE_USERINFO_HOST,
            "/oauth2/v1/userinfo?alt=json",
            {"Authorization": "Bearer " + at}, up=_gupstream())
        if st == 200 and body:
            return (json.loads(body).get("email") or "").strip() or None
    except Exception:
        pass
    return None


def _gcode_call(p, op, obj, at):
    """经账号代理调 cloudcode-pa v1internal:op。返回 (status, json|{})。"""
    body = json.dumps(obj).encode()
    st, raw = _req_via(
        p, "POST", GCODE_HOST, "/v1internal:" + op, {
            "Authorization": "Bearer " + at,
            "Content-Type": "application/json",
            "User-Agent": GCODE_UA,
            "X-Goog-Api-Client": GCODE_API_CLIENT,
            "Client-Metadata": GCODE_META}, body, up=_gupstream())
    try:
        return st, json.loads(raw) if raw else {}
    except Exception:
        return st, {}


def _g_project_id(p, at, log=None):
    """loadCodeAssist → cloudaicompanionProject; 空则 onboardUser
    轮询开通 (照 CPA FetchProjectID/OnboardUser)。返回 (pid, err)。"""
    try:
        st, j = _gcode_call(p, "loadCodeAssist",
                            {"metadata": json.loads(GCODE_META_ONBOARD)},
                            at)
    except Exception as e:
        return None, "loadCodeAssist: " + str(e)[:120]
    if st != 200:
        return None, "loadCodeAssist HTTP %d: %s" % (
            st, str(j)[:160])
    pid = ""
    cp = j.get("cloudaicompanionProject")
    if isinstance(cp, str):
        pid = cp.strip()
    elif isinstance(cp, dict):
        pid = (cp.get("id") or "").strip()
    if pid:
        return pid, None
    tier = "legacy-tier"
    for t in (j.get("allowedTiers") or []):
        if isinstance(t, dict) and t.get("isDefault") \
                and (t.get("id") or "").strip():
            tier = t["id"].strip()
            break
    if log:
        log("  无现成 project_id, onboardUser 开通 (tier=%s) ..."
            % tier)
    for _ in range(5):
        try:
            st, j = _gcode_call(p, "onboardUser",
                                {"tierId": tier,
                                 "metadata":
                                 json.loads(GCODE_META_ONBOARD)}, at)
        except Exception as e:
            return None, "onboardUser: " + str(e)[:120]
        if st != 200:
            return None, "onboardUser HTTP %d: %s" % (
                st, str(j)[:160])
        if j.get("done"):
            rp = (j.get("response") or {}).get(
                "cloudaicompanionProject")
            if isinstance(rp, dict):
                pid = (rp.get("id") or "").strip()
            elif isinstance(rp, str):
                pid = rp.strip()
            if pid:
                return pid, None
            # LRO 报 done 但还没回填 —— 开通生效有传播延迟,
            # 等几秒回头再查 loadCodeAssist 几次
            if log:
                log("  onboard done 但没回填 pid, "
                    "重查 loadCodeAssist ...")
            for _ in range(3):
                time.sleep(3)
                try:
                    st2, j2 = _gcode_call(
                        p, "loadCodeAssist",
                        {"metadata": json.loads(
                            GCODE_META_ONBOARD)}, at)
                except Exception:
                    continue
                if st2 != 200:
                    continue
                cp2 = j2.get("cloudaicompanionProject")
                if isinstance(cp2, str):
                    pid = cp2.strip()
                elif isinstance(cp2, dict):
                    pid = (cp2.get("id") or "").strip()
                if pid:
                    return pid, None
            return None, "onboardUser 完成但响应里没 project_id"
        time.sleep(2)
    return None, "onboardUser 轮询超时"


def _gcred(j, email, pid, proxy_url):
    """token 响应 → CPA antigravity 凭证 JSON (照池内现存文件格式)。
    pid 拿不到时整个 project_id 键省略 —— 写 "" 会让 CPA 的
    ensureAntigravityProjectID (!=nil 判断) 永不懒取; 键缺席才会
    在下次刷新时用 access_token 重查补上。"""
    now = time.time()
    cred = {
        "type": "antigravity",
        "email": email,
        "access_token": j.get("access_token") or "",
        "refresh_token": j.get("refresh_token") or "",
        "expires_in": int(j.get("expires_in") or 0),
        "expired": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                 time.gmtime(
                                     now + int(j.get("expires_in")
                                               or 0))),
        "timestamp": int(now * 1000),
        "proxy_url": proxy_url}
    if pid:
        cred["project_id"] = pid
    return cred


def _gcred_name(cred):
    return "antigravity-%s.json" % (
        (cred.get("email") or "unknown").strip())


def _goauth_expire(accs):
    """同 _oauth_expire, 但落 gaccounts.json。"""
    cut = time.strftime("%Y-%m-%dT%H:%M:%S",
                        time.localtime(time.time()
                                       - _goauth_ttl_s()))
    changed = False
    for a in accs:
        if a.get("cpa") == "pending" \
                and (not a.get("oauth_at") or a["oauth_at"] < cut):
            a["cpa"] = "expired"
            for k in ("oauth_url", "oauth_state", "oauth_at"):
                a.pop(k, None)
            changed = True
    if changed:
        _save_gaccounts(accs)
    return changed


def _goauth_finish(p, a, code, log):
    """code → token → userinfo → project_id → 凭证落账号。
    全程经账号代理 (与登录/回调同 IP)。返回 err|None。"""
    j, err = _goauth_exchange(p, code)
    if err:
        return "换token: " + err
    email = _g_userinfo(p, j["access_token"]) or a["email"]
    if email.lower() != a["email"].lower():
        log("  ⚠ 授权邮箱 %s 与账号 %s 不一致 —— 按账号记"
            % (email, a["email"]))
    pid, err = _g_project_id(p, j["access_token"], log)
    if err:
        # rt/at 已到手 —— project_id 缺不阻塞出凭证:
        # 键省略, CPA 下次刷新用 proxy_url 同IP懒补
        a["cred_warn"] = "project_id: " + err + " (CPA刷新时自补)"
        log("  ⚠ project_id 拿不到 (%s) —— 凭证照出, "
            "CPA 首刷时自补" % err)
    else:
        a.pop("cred_warn", None)
    cred = _gcred(j, a["email"], pid or "", _proxy_url(p, "url"))
    a["cred"] = cred
    a["cred_file"] = _gcred_name(cred)
    a["cred_at"] = _now()
    a["cpa"] = "ready"
    for k in ("oauth_url", "oauth_state", "oauth_at"):
        a.pop(k, None)
    log("✓ %s: token%s 到手, 凭证 %s 已备好"
        % (a["email"],
           "+project_id(%s)" % pid if pid else "(project_id待补)",
           a["cred_file"]))
    # G设置开了自动推 → 直接入 CPA 池, 失败留 ready 态可手动推
    if _gsettings().get("cpa_autopush", True):
        err = _cpa_push_cred(a["cred_file"], cred, st=_gsettings())
        if err:
            log("  ⚠ %s: 自动推入池失败 %s —— 凭证在, 可手动推"
                % (a["email"], err))
        else:
            a["cpa"] = "yes"
            a["cpa_at"] = _now()
            log("  ✓ %s: 已自动推入 CPA 池" % a["email"])
    return None


# -------- OAuth 回调: 常驻 127.0.0.1:51121 接收器 --------
# Google 授权完成后浏览器重定向 localhost:51121/oauth-callback?code=..
# —— 我们直接接住, 不依赖 Playwright 事件; 端口被占才退回页面监听。
GOAUTH_CB = {}          # state -> {"code","at"}
_GCB_SRV = {"srv": None}


def _goauth_cb_server(log=print):
    if _GCB_SRV["srv"]:
        return True

    class _CB(BaseHTTPRequestHandler):
        def do_GET(self):
            p = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(p.query)
            code = (qs.get("code") or [None])[0]
            state = (qs.get("state") or [""])[0]
            if p.path == "/oauth-callback" and code:
                GOAUTH_CB[state] = {"code": code, "at": time.time()}
                body = ("<div style='font-family:sans-serif;text-align:"
                        "center;margin-top:22vh'><h2>✓ 授权已接收</h2>"
                        "<p>系统已拿到回调, 这个标签页可以关了</p></div>"
                        ).encode()
                self.send_response(200)
                self.send_header("Content-Type",
                                 "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, *a):
            pass

    try:
        srv = ThreadingHTTPServer(("127.0.0.1", 51121), _CB)
    except OSError as e:
        log("⚠ :51121 回调接收器绑定失败 (%s) —— "
            "自动截码退化为页面监听" % e)
        return False
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _GCB_SRV["srv"] = srv
    return True


def _goauth_cb_take(state):
    """worker 按自己的 state 取回调 code; 顺带清 >30min 陈旧记录。"""
    now = time.time()
    for k in [k for k, v in GOAUTH_CB.items()
              if now - v["at"] > 1800]:
        GOAUTH_CB.pop(k, None)
    hit = GOAUTH_CB.pop(state, None)
    return (hit or {}).get("code")


# -------- Roxy 窗口页顶助手条: 复制 邮箱/密码/2FA 实时码 --------
_GHELPER_JS = r"""(()=>{
const E=@E@,P=@P@,S=@S@,ID="__ghbar";
let cur="",keyP=null,el=null,dead=false;
const b32d=s=>{s=(s||"").toUpperCase().replace(/[^A-Z2-7]/g,"");const A="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let b=0,v=0;const o=[];for(const c of s){v=(v<<5)|A.indexOf(c);b+=5;if(b>=8){o.push((v>>(b-8))&255);b-=8}}return new Uint8Array(o)};
const cp=(t,c)=>{const old=c.textContent;const lg=()=>{const ta=document.createElement("textarea");ta.value=t;ta.style.cssText="position:fixed;opacity:0;top:0";document.body.appendChild(ta);ta.select();try{document.execCommand("copy")}catch(e){}ta.remove()};const ok=()=>{c.textContent="✓ 已复制";setTimeout(()=>{c.textContent=old},900)};if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(ok).catch(()=>{lg();ok()})}else{lg();ok()}};
const chip=(txt,tip,fn,st)=>{const c=document.createElement("span");c.textContent=txt;c.title=tip||"";c.style.cssText="background:rgba(255,255,255,.13);border:1px solid rgba(255,255,255,.28);border-radius:6px;padding:3px 9px;cursor:pointer;white-space:nowrap;font-family:ui-monospace,monospace;font-size:12px"+(st||"");c.addEventListener("click",ev=>{ev.preventDefault();ev.stopPropagation();fn(c)});return c};
const tick=async()=>{if(!el)return;const left=30-Math.floor(Date.now()/1e3)%30;try{if(!keyP)keyP=crypto.subtle.importKey("raw",b32d(S),{name:"HMAC",hash:"SHA-1"},false,["sign"]);const ctr=new Uint8Array(8);new DataView(ctr.buffer).setUint32(4,Math.floor(Date.now()/3e4));const h=new Uint8Array(await crypto.subtle.sign("HMAC",await keyP,ctr));const o=h[h.length-1]&15;cur=(((h[o]&127)<<24|h[o+1]<<16|h[o+2]<<8|h[o+3])%1e6).toString().padStart(6,"0");el.textContent="验证 "+cur+" ·"+left+"s"}catch(e){el.textContent="验证 --"}};
const mount=()=>{if(dead||document.getElementById(ID)||!document.body)return;const bar=document.createElement("div");bar.id=ID;bar.style.cssText="position:fixed;top:0;left:0;right:0;z-index:2147483647;display:flex;align-items:center;gap:8px;padding:6px 10px;background:rgba(15,23,42,.93);color:#e2e8f0;font:13px/1.4 -apple-system,system-ui,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.4);user-select:none";const tag=document.createElement("b");tag.textContent="助手";tag.style.cssText="color:#7dd3fc;font-size:12px";bar.appendChild(tag);if(E)bar.appendChild(chip(E,"复制邮箱",c=>cp(E,c)));if(P)bar.appendChild(chip("密码 •••","复制密码",c=>cp(P,c)));if(S){el=chip("验证 --","当前 2FA 验证码 —— 点复制",c=>cp(cur,c),";color:#fbbf24");bar.appendChild(el);tick()}const x=document.createElement("span");x.textContent="×";x.title="收起助手条 (页面跳转会再出现)";x.style.cssText="margin-left:auto;cursor:pointer;opacity:.65;font-size:15px;padding:0 4px";x.addEventListener("click",ev=>{ev.stopPropagation();dead=true;el=null;bar.remove()});bar.appendChild(x);document.body.appendChild(bar)};
mount();
if(S)setInterval(tick,1000);
setInterval(mount,2500);
})();"""


def _g_helper_js(a):
    return (_GHELPER_JS
            .replace("@E@", json.dumps(a.get("email") or ""))
            .replace("@P@", json.dumps(a.get("password") or ""))
            .replace("@S@", json.dumps(a.get("totp") or "")))


def _g_inject_helper(pg, a):
    """页顶挂助手条: add_init_script 管后续每次导航重建,
    evaluate 管当前页。"""
    js = _g_helper_js(a)
    try:
        pg.add_init_script(js)
    except Exception:
        pass
    try:
        pg.evaluate(js)
    except Exception:
        pass


GOAUTH_JOB = {"running": False, "log": [], "results": {},
              "stop": False}


def _goauth_worker(ids):
    """逐账号 Google antigravity OAuth: 算链接 → 开 gauto- 窗口
    (同代理) → 截 localhost:51121 回调 → 经账号代理换 token
    + userinfo + project_id → 生成 antigravity 凭证 (含 proxy_url)。
    登录 google/提交回调/凭证生成 全链路同一 IP。"""
    GOAUTH_JOB["running"] = True
    GOAUTH_JOB["stop"] = False
    GOAUTH_JOB["log"] = []
    GOAUTH_JOB["results"] = {}

    def log(m):
        GOAUTH_JOB["log"].append(
            "%s %s" % (time.strftime("%H:%M:%S"), m))

    if _goauth_cb_server(log):
        log("→ :51121 回调接收器在听 —— 浏览器跳转自动接码")
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as pw:
            for aid in ids:
                if GOAUTH_JOB["stop"]:
                    log("⏹ 已手动停止")
                    break
                a = next((x for x in _load_gaccounts()
                          if x["id"] == aid), None)
                if not a or a.get("archived"):
                    continue
                email = a["email"]
                try:
                    px = _load_gproxies()
                    p = next((x for x in px
                              if x["id"] == a.get("proxy_id")),
                             None)
                    if not p or p.get("banned"):
                        # 没绑/绑死了: 现场选一条绑上 —— IP 从这个
                        # 窗口建立起就是这一条, 全链一致
                        p = _pick_proxy(px, email)
                        if not p:
                            cool = (" (冷却中 %d 条)"
                                    % PICK_LAST["cooled"]
                                    if PICK_LAST["cooled"] else "")
                            GOAUTH_JOB["results"][aid] = \
                                "没有可用代理" + cool
                            log("✗ %s: 没有可用代理%s" % (email, cool))
                            continue
                        _bind_proxy(p, email, _gcool_secs())
                        a["proxy_id"] = p["id"]
                        _save_gproxies(px)
                        log("→ %s: 绑代理 %s:%s" % (
                            email, p["host"], p["port"]))
                    url, state = _goauth_gen()
                    a["oauth_state"] = state
                    a["oauth_url"] = url
                    a["oauth_at"] = _now()
                    log("→ %s: Google OAuth 链接已生成 (%d分钟时效)"
                        % (email, _goauth_ttl_s() // 60))
                    dir_id, cws, err = _roxy_open_for(
                        email, p, prefix="gauto",
                        env=_gsettings().get("open_env"))
                    if err or not cws:
                        GOAUTH_JOB["results"][aid] = \
                            "开窗: " + (err or "")
                        log("✗ %s: 开窗失败 %s" % (email, err))
                        continue
                    a["win"] = dir_id
                    cbr = pw.chromium.connect_over_cdp(cws)
                    try:
                        ctx = cbr.contexts[0] if cbr.contexts else None
                        # 授权链接开新标签页 —— 不覆盖原有标签
                        cpg = ctx.new_page() if ctx else None
                        _g_inject_helper(cpg, a)   # 页顶助手条
                        cpg.goto(url, wait_until="domcontentloaded",
                                 timeout=60000)
                        try:
                            cpg.bring_to_front()
                        except Exception:
                            pass
                        code = None
                        hit = {"u": None}

                        def _take(u):
                            if not u or "localhost:51121" not in u:
                                return
                            qs = urllib.parse.parse_qs(
                                urllib.parse.urlparse(u).query)
                            got = (qs.get("state") or [""])[0]
                            if got and got != state:
                                return
                            if qs.get("code"):
                                hit["u"] = u

                        cpg.on("request", lambda r: _take(r.url))
                        cpg.on("requestfailed",
                               lambda r: _take(r.url))
                        cdp = cpg.context.new_cdp_session(cpg)
                        deadline = time.time() + _goauth_ttl_s()
                        while time.time() < deadline:
                            if GOAUTH_JOB["stop"]:
                                break
                            # 主路: :51121 常驻接收器已直接接到回调
                            code = _goauth_cb_take(state)
                            if code:
                                log("  %s: :51121 接收器拿到回调"
                                    % email)
                                break
                            if hit["u"]:
                                code = (urllib.parse.parse_qs(
                                    urllib.parse.urlparse(
                                        hit["u"]).query)
                                    .get("code") or [None])[0]
                                break
                            _take(cpg.url or "")
                            try:
                                for e in (cdp.send(
                                        "Page.getNavigationHistory")
                                        .get("entries") or []):
                                    _take(e.get("url"))
                            except Exception:
                                pass
                            if hit["u"]:
                                continue
                            # Google 同意页按钮尽力点 (Continue/允许)
                            for sel in (
                                    'button:has-text("Continue")',
                                    'button:has-text("Allow")',
                                    'button:has-text("允许")',
                                    'button:has-text("继续")',
                                    'button[type="submit"]'):
                                try:
                                    b = cpg.query_selector(sel)
                                    if b and b.is_visible():
                                        b.click()
                                        log("  %s: 点了授权按钮 %s"
                                            % (email, sel))
                                        cpg.wait_for_timeout(1500)
                                        break
                                except Exception:
                                    pass
                            cpg.wait_for_timeout(2000)
                        if not code:
                            if GOAUTH_JOB["stop"]:
                                a["cpa"] = "pending"
                                done = "手动停止"
                            else:
                                a["cpa"] = "expired"
                                for k in ("oauth_url", "oauth_state",
                                          "oauth_at"):
                                    a.pop(k, None)
                                done = "授权超时 (链接已过时效)"
                            GOAUTH_JOB["results"][aid] = done
                            log("✗ %s: %s%s" % (email, done,
                                ", 授权页留在窗口里"
                                if GOAUTH_JOB["stop"]
                                else ", 重跑OAuth授权"))
                            continue
                        log("  %s: 回调已截获, 走账号代理换 token"
                            % email)
                        err = _goauth_finish(p, a, code, log)
                        if err:
                            a["cpa"] = "pending"
                            GOAUTH_JOB["results"][aid] = err
                            log("✗ %s: %s" % (email, err))
                            continue
                        GOAUTH_JOB["results"][aid] = "凭证已生成"
                    finally:
                        try:
                            cbr.close()
                        except Exception:
                            pass
                except Exception as e:
                    GOAUTH_JOB["results"][aid] = str(e)[:120]
                    log("✗ %s: %s" % (email, str(e)[:120]))
                finally:
                    accs_all = _load_gaccounts()
                    for x in accs_all:
                        if x["id"] == aid:
                            x.clear(); x.update(a)
                            break
                    _save_gaccounts(accs_all)
    finally:
        GOAUTH_JOB["running"] = False
        log("—— Google OAuth 授权结束 ——"
            + (" (手动停止)" if GOAUTH_JOB["stop"] else ""))


GOPEN_JOB = {"running": False, "log": [], "results": {},
             "stop": False}
GOOGLE_START_URL = "https://accounts.google.com/"


def _gopen_worker(accs):
    """低级半自动: 选代理 -> 绑定 -> 开 gauto- 窗口 -> 打开 Google
    登录页即交人工 (不做任何表单自动化)。代理选取与 GPT 共用同一
    池子同一冷却语义。"""
    GOPEN_JOB["running"] = True
    GOPEN_JOB["stop"] = False
    GOPEN_JOB["log"] = []
    GOPEN_JOB["results"] = {}
    log = GOPEN_JOB["log"].append
    db_lock = threading.Lock()

    def _persist(a):
        with db_lock:
            all_ = _load_gaccounts()
            for x in all_:
                if x["id"] == a["id"]:
                    x.clear(); x.update(a)
                    break
            _save_gaccounts(all_)

    def _one(a):
        email = a["email"]
        try:
            with db_lock:
                px = _load_gproxies()
                p = next((x for x in px
                          if x["id"] == a.get("proxy_id")), None)
                if p and not p.get("banned"):
                    bound = False
                else:
                    p = _pick_proxy(px, email)
                    bound = True
                    if p:
                        _bind_proxy(p, email, _gcool_secs())
                        a["proxy_id"] = p["id"]
                        _save_gproxies(px)
            if not p:
                cool = (" (冷却中 %d 条)" % PICK_LAST["cooled"]
                        if PICK_LAST["cooled"] else "")
                GOPEN_JOB["results"][a["id"]] = "没有可用代理" + cool
                log(f"✗ {email}: 没有可用代理{cool}")
                return
            if bound:
                log(f"→ {email}: 绑代理 {p['host']}:{p['port']}"
                    f" (占用 {_bound_count(p)}/{PICK_LIMIT})")
            dir_id, ws, err = _roxy_open_for(
                email, p, prefix="gauto",
                env=_gsettings().get("open_env"))
            if err:
                with db_lock:
                    _unbind_proxy(p, email, _gcool_secs())
                    p["alive"] = False
                    a["proxy_id"] = None
                    _save_gproxies(px)
                GOPEN_JOB["results"][a["id"]] = err
                log(f"✗ {email}: 开窗失败 {err}"
                    f" (已解绑换代理重试即可)")
                return
            a["win"] = dir_id
            r = _roxy_goto_url(ws, GOOGLE_START_URL,
                               _g_helper_js(a))
            a["status"] = "opened"
            GOPEN_JOB["results"][a["id"]] = "已开到 Google 登录页"
            log(f"✓ {email}: 已开到 accounts.google.com, "
                f"页顶助手条可抄 邮箱/密码/2FA码 —— "
                f"登录/授权全人工; 要跑 antigravity 授权点「OAuth授权」")
        except Exception as e:
            GOPEN_JOB["results"][a["id"]] = str(e)[:120]
            log(f"✗ {email}: {str(e)[:120]}")
        finally:
            _persist(a)

    try:
        with ThreadPoolExecutor(
                max_workers=_open_workers()) as ex:
            futs = []
            for a in accs:
                if GOPEN_JOB["stop"]:
                    log("⏹ 已手动停止")
                    break
                futs.append(ex.submit(_one, a))
            for f in futs:
                f.result()
    finally:
        GOPEN_JOB["running"] = False
        log("—— 全部结束 ——"
            + (" (手动停止)" if GOPEN_JOB["stop"] else ""))


# ---------------- 开窗任务 ----------------
OPEN_JOB = {"running": False, "log": [], "results": {},
            "stop": False}
TARGET_URL = "https://chatgpt.com"


OPEN_WORKERS = 3          # 并行开窗默认并发数 (设置页 open_workers 可改)


def _open_workers():
    """开窗并发: 设置页 open_workers, 夹 1..10, 非法值回落默认。"""
    try:
        return max(1, min(10, int(
            _settings().get("open_workers") or OPEN_WORKERS)))
    except Exception:
        return OPEN_WORKERS


REG_WAIT_SECS = 30 * 60   # 开窗后等注册完成确认的最长时长

# 注册落地信号: chatgpt.com 页 /api/auth/session 带 user = 已登录。
# (登出页也可能渲染输入框, DOM 不可靠; session 空/401 即未完成)
_REG_DONE_JS = ("fetch('/api/auth/session',{credentials:'include'})"
                ".then(r=>r.ok?r.json():null)"
                ".then(s=>s&&s.user?'session':null)"
                ".catch(()=>null)")


def _open_worker(accs):
    """并行: 选代理 -> 绑定 -> Roxy 开窗 -> 跳 chatgpt.com -> 按设置
    页「开窗自动化」勾选的步骤依次自动执行 (接码监听 / 资料生成 /
    邮箱提交 / 填码 / 创建密码 / 填资料), 没勾的留人工。
    db_lock 保护代理选取/绑定和 JSON 落盘 —— 避免并发抢同一代理
    或互相覆盖写文件。"""
    _st = _settings()
    step_watch = _st.get("step_watch", True)
    step_gen = _st.get("step_gen", True)
    step_email = _st.get("step_email", True)
    step_code = _st.get("step_code", True)
    step_pwd = _st.get("step_password", True)
    step_profile = _st.get("step_profile", True)
    OPEN_JOB["running"] = True
    OPEN_JOB["stop"] = False
    OPEN_JOB["log"] = []
    OPEN_JOB["results"] = {}
    log = OPEN_JOB["log"].append
    db_lock = threading.Lock()

    def _stopped():
        return OPEN_JOB["stop"]

    def _persist(a):
        # a 是 _load_accounts() 的副本 -> 写回存储里的同 id 条目
        with db_lock:
            accs_all = _load_accounts()
            for x in accs_all:
                if x["id"] == a["id"]:
                    x.clear(); x.update(a)
                    break
            _save_accounts(accs_all)

    def _process(a):
        email = a["email"]
        if _stopped():
            return
        try:
            with db_lock:
                px = _load_proxies()
                p = next((x for x in px
                          if x["id"] == a.get("proxy_id")), None)
                if p and not p.get("banned"):
                    bound = False
                else:
                    p = _pick_proxy(px, email)
                    bound = True
                    if p:
                        _bind_proxy(p, email)
                        a["proxy_id"] = p["id"]
                        _save_proxies(px)
            if not p:
                cool = (" (冷却中 %d 条)" % PICK_LAST["cooled"]
                        if PICK_LAST["cooled"] else "")
                OPEN_JOB["results"][a["id"]] = "没有可用代理" + cool
                log(f"✗ {email}: 没有可用代理{cool}")
                return
            if bound:
                log(f"→ {email}: 绑代理 "
                    f"{p['scheme']}://{p['host']}:{p['port']} "
                    f"(占用 {_bound_count(p)}/{PICK_LIMIT})")
            else:
                log(f"→ {email}: 沿用已绑代理 {p['host']}:{p['port']}")
            dir_id, ws, err = _roxy_open_for(email, p)
            if err:
                # 开窗失败: 解绑让账号下次换一条, 顺手把代理标死
                with db_lock:
                    _unbind_proxy(p, email)
                    p["alive"] = False
                    a["proxy_id"] = None
                    _save_proxies(px)
                OPEN_JOB["results"][a["id"]] = err
                log(f"✗ {email}: 开窗失败 {err} (已解绑换代理重试即可)")
                return
            a["win"] = dir_id
            r = _chatgpt_goto(ws, _gpt_helper_js(a))
            if r != "ok":
                a["status"] = "login_failed"
                OPEN_JOB["results"][a["id"]] = r
                log(f"✗ {email}: 导航失败 — {r}")
                return
            a["status"] = "opened"
            OPEN_JOB["results"][a["id"]] = "已定位, 请手动操作"
            log(f"✓ {email}: 已开到 chatgpt.com")
            if step_watch and _mail_watch_start(a):
                log(f"  [{email}] 📨 接码监听已开 (10min)")
            if step_gen:
                _prof_gen_start(a)
                log(f"  [{email}] 🤖 资料生成中 …")
            if step_email:
                r2 = _chatgpt_email_step(
                    ws, a, lambda m: log(f"  [{email}] {m}"),
                    should_stop=_stopped)
                if r2 == "ok":
                    log(f"  [{email}] ✉ 自动输入邮箱完成")
                else:
                    log(f"  [{email}] ✉ 自动输入邮箱失败: {r2}"
                        f" —— 请手动继续")
            if step_code and not a.get("email_dead"):
                r3 = _chatgpt_code_step(
                    ws, a, lambda m: log(f"  [{email}] {m}"),
                    _upstream(), should_stop=_stopped,
                    auto_password=step_pwd)
                if r3 == "ok":
                    log(f"  [{email}] 🔢 验证码已提交")
                elif r3 == "ok_passed":
                    log(f"  [{email}] 验证码页已被人工越过")
                elif r3 == "email_dead":
                    a["status"] = "email_dead"
                    a["email_dead"] = True
                    log(f"  [{email}] ✗ 邮箱不可用 (602)"
                        f" —— 后续步骤全部跳过")
                elif r3 == "no_mail":
                    log(f"  [{email}] 🔢 无接码链接, 跳过自动填码")
                elif r3 != "stopped":
                    log(f"  [{email}] 🔢 自动填码失败: {r3}"
                        f" —— 请手动继续")
            # 创建密码页也可能出现在验证码之后 (码前的已在填码步骤内联)
            if step_pwd and not a.get("email_dead"):
                r5 = _chatgpt_password_step(
                    ws, a, lambda m: log(f"  [{email}] {m}"),
                    should_stop=_stopped)
                if r5 not in ("ok", "no_pwd", "stopped"):
                    log(f"  [{email}] 🔑 创建密码失败: {r5}"
                        f" —— 请手动继续")
            if step_profile and not a.get("email_dead"):
                r4 = _chatgpt_profile_step(
                    ws, a, lambda m: log(f"  [{email}] {m}"),
                    should_stop=_stopped)
                if r4 == "ok":
                    a["reg"] = "new"
                    a["reg_at"] = _now()
                    log(f"  [{email}] 📝 自动填资料完成"
                        f" —— 注册应已落地")
                elif r4 == "ok_passed":
                    log(f"  [{email}] 资料页已被人工越过")
                elif r4 != "stopped":
                    log(f"  [{email}] 📝 自动填资料失败: {r4}"
                        f" —— 请手动继续")
            # 串行关键: 未标记注册的号原地等待, 直到 ——
            # A) 页面实况认到已登录主界面 (api/auth/session 有 user)
            # B) 人工在接码面板点「完成注册/跳过」
            # C) 窗口连不上(关了)/超时/手动停止 → 放行
            # reg_skip 进窗先清, 防上次跳过状态卡死本次等待。
            if not a.get("reg") and not a.get("email_dead") \
                    and not _stopped():
                a.pop("reg_skip", None)
                _persist(a)
                # 没开接码监听的也留一条面板行 ——
                # 不然「完成注册/跳过」没地方点
                MAIL_WATCH.setdefault(
                    a["id"], {"email": email, "running": False,
                              "code": None, "at": None,
                              "dead": False, "stop": False})
                log(f"  [{email}] ⏸ 等注册完成信号 "
                    "(登录态自动识别 / 面板「完成注册/跳过」)")
                t0 = time.time()
                done_how = None
                from playwright.sync_api import sync_playwright
                try:
                    with sync_playwright() as pw:
                        brw, bad_cdp = None, 0
                        while not _stopped() \
                                and time.time() - t0 < REG_WAIT_SECS:
                            # 信号B: 人工标记 (面板按钮写账号记录)
                            cur = next((x for x in _load_accounts()
                                        if x["id"] == a["id"]),
                                       None) or {}
                            if cur.get("reg") in ("new", "yes"):
                                a["reg"] = cur["reg"]
                                a["reg_at"] = cur.get("reg_at")
                                done_how = "人工确认"
                                break
                            if cur.get("reg_skip") \
                                    or cur.get("email_dead"):
                                if cur.get("email_dead"):
                                    a["email_dead"] = True
                                    a["status"] = "email_dead"
                                done_how = "人工跳过/邮箱失效"
                                break
                            # 信号A: 页面实况 —— 任一 chatgpt.com
                            # 标签页带登录态即判完成
                            try:
                                if brw is None:
                                    brw = pw.chromium \
                                        .connect_over_cdp(ws)
                                hit = None
                                for ctx0 in brw.contexts:
                                    for pg0 in ctx0.pages:
                                        if "chatgpt.com" not in \
                                                (pg0.url or ""):
                                            continue
                                        try:
                                            hit = pg0.evaluate(
                                                _REG_DONE_JS)
                                        except Exception:
                                            pass
                                        if hit:
                                            break
                                    if hit:
                                        break
                                bad_cdp = 0
                                if hit:
                                    a["reg"] = "new"
                                    a["reg_at"] = _now()
                                    done_how = "登录态自动识别"
                                    break
                            except Exception:
                                bad_cdp += 1
                                try:
                                    brw.close()
                                except Exception:
                                    pass
                                brw = None
                                if bad_cdp >= 3:
                                    done_how = "窗口已关/连不上"
                                    break
                            time.sleep(3)
                except Exception as e2:
                    log(f"  [{email}] 等待轮询异常: "
                        f"{str(e2)[:80]}")
                if done_how:
                    log(f"  [{email}] ✓ {done_how} → 下一个")
                    if a.get("reg") in ("new", "yes"):
                        OPEN_JOB["results"][a["id"]] = \
                            f"已注册({done_how})"
                    elif done_how == "人工跳过/邮箱失效":
                        OPEN_JOB["results"][a["id"]] = "已跳过"
                else:
                    log(f"  [{email}] ⏸ 等确认结束 "
                        f"(超时 {REG_WAIT_SECS // 60}min 或已停止)"
                        " → 放行")
        except Exception as e:
            OPEN_JOB["results"][a["id"]] = str(e)[:120]
            log(f"✗ {email}: {str(e)[:120]}")
        finally:
            _persist(a)
    try:
        with ThreadPoolExecutor(
                max_workers=_open_workers()) as ex:
            futs = []
            for a in accs:
                if _stopped():
                    log("⏹ 已手动停止")
                    break
                futs.append(ex.submit(_process, a))
            for f in futs:
                f.result()
    finally:
        OPEN_JOB["running"] = False
        log("—— 全部结束 ——" + (" (手动停止)" if OPEN_JOB["stop"] else ""))


# ---------------- HTTP ----------------
PAGES = {"/": "index.html", "/index.html": "index.html",
         "/mothers": "mothers.html", "/mothers.html": "mothers.html",
         "/accounts": "accounts.html", "/accounts.html": "accounts.html",
         "/g": "gaccounts.html", "/g/accounts": "gaccounts.html",
         "/gaccounts.html": "gaccounts.html",
         "/g/proxies": "gproxies.html",
         "/gproxies.html": "gproxies.html",
         "/g/settings": "gsettings.html",
         "/gsettings.html": "gsettings.html",
         "/settings": "settings.html", "/settings.html": "settings.html"}
STATICS = {"/ui.css": ("ui.css", "text/css; charset=utf-8"),
           "/ui.js": ("ui.js", "application/javascript; charset=utf-8")}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200, cors=False):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=utf-8")
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_OPTIONS(self):
        # 页内助手条轮询 /api/helper: 公网页 -> 127.0.0.1 私有网络,
        # Chrome PNA 预检要求 Access-Control-Allow-Private-Network
        if self.path.startswith("/api/helper"):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods",
                             "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Private-Network",
                             "true")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_error(404)

    def _body(self):
        n = int(self.headers.get("content-length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _file(self, name, ctype="text/html; charset=utf-8"):
        try:
            b = open(os.path.join(BASE_DIR, name), "rb").read()
        except OSError:
            return self.send_error(404)
        self.send_response(200)
        self.send_header("content-type", ctype)
        # 本地管理页随时在改: 禁启发式缓存, 否则旧页面缺新功能
        self.send_header("Cache-Control", "no-cache")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in PAGES:
            return self._file(PAGES[self.path])
        if self.path in STATICS:
            f, ct = STATICS[self.path]
            return self._file(f, ct)
        if self.path == "/api/proxies":
            px = _load_proxies()
            stats = {"total": len(px),
                     "avail": sum(1 for p in px if not p.get("banned")),
                     "banned": sum(1 for p in px if p.get("banned")),
                     "alive": sum(1 for p in px if p.get("alive")),
                     "bound": sum(len(p.get("bound") or [])
                                  for p in px)}
            return self._json({"proxies": px, "stats": stats,
                               "upstream":
                                   (_settings().get("upstream_proxy")
                                    or "")})
        if self.path == "/api/settings":
            s = _settings()
            return self._json({
                "upstream_proxy": s.get("upstream_proxy") or "",
                "namegen_enabled": bool(s.get("namegen_enabled")),
                "namegen_url": s.get("namegen_url") or "",
                "namegen_model": s.get("namegen_model") or "",
                "namegen_key": s.get("namegen_key") or "",
                "namegen_prompt": s.get("namegen_prompt")
                or NAMEGEN_PROMPT,
                "pace_step_min": s.get("pace_step_min") or 2.0,
                "pace_step_max": s.get("pace_step_max") or 6.0,
                "pace_type_min": s.get("pace_type_min") or 90,
                "pace_type_max": s.get("pace_type_max") or 240,
                "pace_load_ms": s.get("pace_load_ms") or 5000,
                "proxy_cool_min": s.get("proxy_cool_min") or 20,
                "oauth_ttl_min": s.get("oauth_ttl_min") or 10,
                "open_workers": s.get("open_workers") or OPEN_WORKERS,
                "open_env": s.get("open_env") or "pc-random",
                "step_watch": s.get("step_watch", True),
                "step_gen": s.get("step_gen", True),
                "step_email": s.get("step_email", True),
                "step_code": s.get("step_code", True),
                "step_password": s.get("step_password", True),
                "step_profile": s.get("step_profile", True),
                "cpa_url": s.get("cpa_url") or "",
                "cpa_key": s.get("cpa_key") or "",
                "cpa_autopush": s.get("cpa_autopush", True)})
        if self.path == "/api/accounts":
            accs = _load_accounts()
            _oauth_expire(accs)   # pending 超时 → expired
            px = _load_proxies()
            pmap = {p["id"]: p for p in px}
            out = []
            for a in accs:
                p = pmap.get(a.get("proxy_id") or "")
                out.append({**a,
                            "email_dead":
                                a.get("email_dead")
                                or a.get("status") == "email_dead"
                                or (MAIL_WATCH.get(a["id"]) or {})
                                      .get("dead", False),
                            "proxy":
                                (f"{p['scheme']}://{p['host']}:{p['port']}"
                                 if p else None)})
            stats = {"total": len(accs),
                     "archived": sum(1 for a in accs
                                     if a.get("archived")),
                     "bound": sum(1 for a in accs if a.get("proxy_id")),
                     "opened": sum(1 for a in accs if a.get("win")),
                     "reg": sum(1 for a in accs
                                if a.get("reg") in ("new", "yes")),
                     "unbound": sum(1 for a in accs
                                    if not a.get("proxy_id"))}
            return self._json({"accounts": out, "stats": stats,
                               "target": TARGET_URL,
                               "oauth_ttl_min": _oauth_ttl_s() // 60})
        if self.path == "/api/accounts/open/status":
            return self._json({"running": OPEN_JOB["running"],
                               "log": OPEN_JOB["log"][-80:],
                               "results": OPEN_JOB["results"]})
        if self.path == "/api/accounts/pat/status":
            return self._json({"running": PAT_JOB["running"],
                               "log": PAT_JOB["log"][-80:],
                               "results": PAT_JOB["results"]})
        if self.path == "/api/accounts/ios-reg/status":
            return self._json({"running": IOS_JOB["running"],
                               "log": IOS_JOB["log"][-80:],
                               "results": IOS_JOB["results"]})
        if self.path == "/api/accounts/proto-pat/status":
            return self._json(
                {"running": PROTO_PAT_JOB["running"],
                 "log": PROTO_PAT_JOB["log"][-80:],
                 "results": PROTO_PAT_JOB["results"]})
        if self.path == "/api/mail-codes":
            # 接码监听列表 (清掉 30min 前的死条目)
            now = time.time()
            for aid in [k for k, v in MAIL_WATCH.items()
                        if not v.get("running") and v.get("ts_done")
                        and now - v["ts_done"] > 1800]:
                MAIL_WATCH.pop(aid, None)
            for aid in [k for k, v in PROF_WATCH.items()
                        if now - v.get("ts", 0) > 3600]:
                PROF_WATCH.pop(aid, None)
            return self._json({"watch": [
                {"id": k, **{x: v[x] for x in
                             ("email", "running", "code", "at", "dead")
                             if x in v}}
                for k, v in MAIL_WATCH.items()
                if not v.get("hidden")],
                "profiles": [
                    {"id": k, **v} for k, v in PROF_WATCH.items()]})
        if self.path.startswith("/api/helper"):
            # 页内助手条轮询源: 邮箱验证码/接码状态/资料/密码 实时值
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            em = (qs.get("email") or [""])[0].lower()
            a = next((x for x in _load_accounts()
                      if (x.get("email") or "").lower() == em), None)
            if not a:
                return self._json({"found": False}, cors=True)
            mw = MAIL_WATCH.get(a["id"]) or {}
            pv = PROF_WATCH.get(a["id"]) or {}
            return self._json({
                "found": True,
                "code": mw.get("code"), "code_at": mw.get("at"),
                "mail_dead": bool(mw.get("dead") or a.get("email_dead")),
                "mail_running": bool(mw.get("running")),
                "name": pv.get("name")
                        or (a.get("extra") or "").strip() or None,
                "age": pv.get("age"),
                "password": a.get("password") or None}, cors=True)
        if self.path == "/api/g/accounts":
            accs = _load_gaccounts()
            _goauth_expire(accs)
            px = _load_gproxies()
            pmap = {p["id"]: p for p in px}
            out = []
            for a in accs:
                p = pmap.get(a.get("proxy_id") or "")
                d = {**a,
                     "proxy":
                         (f"{p['scheme']}://{p['host']}:{p['port']}"
                          if p else None)}
                if a.get("totp"):
                    d["totp_code"] = _totp_code(a["totp"])
                    d["totp_left"] = 30 - int(time.time() % 30)
                out.append(d)
            stats = {"total": len(accs),
                     "archived": sum(1 for a in accs
                                     if a.get("archived")),
                     "bound": sum(1 for a in accs if a.get("proxy_id")),
                     "opened": sum(1 for a in accs if a.get("win")),
                     "ready": sum(1 for a in accs
                                  if a.get("cpa") == "ready"),
                     "pushed": sum(1 for a in accs
                                   if a.get("cpa") == "yes")}
            return self._json({"accounts": out, "stats": stats,
                               "oauth_ttl_min": _goauth_ttl_s() // 60})
        if self.path == "/api/g/open/status":
            return self._json({"running": GOPEN_JOB["running"],
                               "log": GOPEN_JOB["log"][-80:],
                               "results": GOPEN_JOB["results"]})
        if self.path == "/api/g/oauth/status":
            return self._json(GOAUTH_JOB)
        if self.path == "/api/g/proxies":
            px = _load_gproxies()
            stats = {"total": len(px),
                     "avail": sum(1 for p in px if not p.get("banned")),
                     "banned": sum(1 for p in px if p.get("banned")),
                     "alive": sum(1 for p in px if p.get("alive")),
                     "bound": sum(len(p.get("bound") or [])
                                  for p in px)}
            return self._json({"proxies": px, "stats": stats,
                               "upstream":
                                   (_gsettings().get("upstream_proxy")
                                    or "")})
        if self.path.startswith("/api/g/proxies/export"):
            q = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            fmt = (q.get("fmt") or ["colon"])[0]
            ids = set((q.get("ids") or [""])[0].split(",")) - {""}
            px = [p for p in _load_gproxies()
                  if not ids or p["id"] in ids]
            if fmt == "json":
                b = json.dumps(px, ensure_ascii=False,
                               indent=1).encode()
                ext, ct = "json", "application/json"
            else:
                b = ("\n".join(_proxy_url(p, fmt) for p in px)
                     + "\n").encode()
                ext, ct = "txt", "text/plain; charset=utf-8"
            self.send_response(200)
            self.send_header("content-type", ct)
            self.send_header("content-disposition",
                             'attachment; filename="gproxies.%s"'
                             % ext)
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if self.path == "/api/g/settings":
            s = _gsettings()
            return self._json({
                "upstream_proxy": s.get("upstream_proxy") or "",
                "proxy_cool_min": s.get("proxy_cool_min") or 20,
                "oauth_ttl_min": s.get("oauth_ttl_min") or 10,
                "open_env": s.get("open_env") or "pc-random",
                "cpa_url": s.get("cpa_url") or "",
                "cpa_key": s.get("cpa_key") or "",
                "cpa_autopush": s.get("cpa_autopush", True)})
        m = re.fullmatch(r"/api/g/accounts/([0-9a-f-]+)/cred",
                         self.path)
        if m:
            a = next((x for x in _load_gaccounts()
                      if x["id"] == m.group(1)), None)
            if not a or not a.get("cred"):
                return self._json({"error": "没有凭证"}, 404)
            data = json.dumps(a["cred"], ensure_ascii=False,
                              indent=2).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header(
                "content-disposition",
                'attachment; filename="%s"'
                % (a.get("cred_file") or "antigravity-cred.json"))
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/api/g/cred-export"):
            q = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            ids = set((q.get("ids") or [""])[0].split(",")) - {""}
            items = [
                (a.get("cred_file") or _gcred_name(a["cred"]),
                 a["cred"])
                for a in _load_gaccounts()
                if a.get("cred")
                and (not ids or a["id"] in ids)]
            if not items:
                return self._json({"error": "没有可导出的凭证"}, 404)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w",
                                 zipfile.ZIP_DEFLATED) as z:
                for name, cred in items:
                    z.writestr(name, json.dumps(
                        cred, ensure_ascii=False, indent=2))
            data = buf.getvalue()
            self.send_response(200)
            self.send_header("content-type", "application/zip")
            self.send_header(
                "content-disposition",
                'attachment; filename="antigravity-creds.zip"')
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/api/mother":
            s = _settings()
            return self._json({"mother_window":
                               s.get("mother_window") or "",
                               "mother_workspace":
                               s.get("mother_workspace") or "",
                               "mother_workspace_name":
                               s.get("mother_workspace_name") or ""})
        if self.path == "/api/mother/workspaces":
            """连 Pat测试母号窗口列出她拥有的 workspace (给下拉选择用)。"""
            email, wss, err = _list_workspaces(None)
            if err:
                return self._json({"error": err})
            return self._json({"email": email, "workspaces": wss})
        if self.path == "/api/mothers":
            return self._json({"mothers": _space_mothers()})
        if self.path.startswith("/api/mothers/workspaces"):
            """连指定空间母号窗口列出她的 workspace。"""
            q = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            name = (q.get("name") or [""])[0].strip()
            if not name:
                return self._json({"error": "缺 name 参数"})
            email, wss, err = _list_workspaces(name)
            if err:
                return self._json({"error": err})
            return self._json({"email": email, "workspaces": wss})
        if self.path == "/api/accounts/join/status":
            return self._json(JOIN_JOB)
        if self.path == "/api/accounts/leave/status":
            return self._json(LEAVE_JOB)
        if self.path == "/api/accounts/cpa/status":
            return self._json(CPA_JOB)
        m = re.fullmatch(r"/api/accounts/([0-9a-f-]+)/cred",
                         self.path)
        if m:
            a = next((x for x in _load_accounts()
                      if x["id"] == m.group(1)), None)
            if not a or not a.get("cred"):
                return self._json({"error": "没有凭证"}, 404)
            data = json.dumps(a["cred"], ensure_ascii=False,
                              indent=2).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header(
                "content-disposition",
                'attachment; filename="%s"'
                % (a.get("cred_file") or "codex-cred.json"))
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/api/accounts/cred-export"):
            q = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query)
            ids = set((q.get("ids") or [""])[0].split(",")) - {""}
            items = [
                (a.get("cred_file") or _cred_name(a["cred"]),
                 a["cred"])
                for a in _load_accounts()
                if a.get("cred")
                and (not ids or a["id"] in ids)]
            if not items:
                return self._json(
                    {"error": "没有可导出的凭证 (先跑🔗OAuth授权)"},
                    404)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w",
                                 zipfile.ZIP_DEFLATED) as z:
                for name, cred in items:
                    z.writestr(name, json.dumps(
                        cred, ensure_ascii=False, indent=2))
            data = buf.getvalue()
            self.send_response(200)
            self.send_header("content-type", "application/zip")
            self.send_header(
                "content-disposition",
                'attachment; filename="cpa-creds-%s.zip"'
                % time.strftime("%m%d-%H%M"))
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/api/proxies/export"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            fmt = (q.get("fmt") or ["colon"])[0]
            ids = set((q.get("ids") or [""])[0].split(",")) - {""}
            px = [p for p in _load_proxies() if not ids or p["id"] in ids]
            if fmt == "json":
                b = json.dumps(px, ensure_ascii=False, indent=1).encode()
                ext, ct = "json", "application/json"
            else:
                b = ("\n".join(_proxy_url(p, fmt) for p in px)
                     + "\n").encode()
                ext, ct = "txt", "text/plain; charset=utf-8"
            self.send_response(200)
            self.send_header("content-type", ct)
            self.send_header("content-disposition",
                             f'attachment; filename="proxies.{ext}"')
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        self.send_error(404)

    def do_POST(self):
        if self.path == "/api/proxies/import":
            try:
                req = self._body()
            except Exception:
                return self._json({"error": "请求体不是 JSON"}, 400)
            text = req.get("text") or ""
            default_scheme = req.get("scheme") or "socks5"
            px = _load_proxies()
            seen = {_proxy_key(p) for p in px}
            added, dup, bad = 0, 0, []
            for i, line in enumerate(text.splitlines(), 1):
                d, err = _parse_proxy_line(line, default_scheme)
                if err in ("empty", "comment"):
                    continue
                if err:
                    bad.append({"line": i, "err": err,
                                "raw": line.strip()[:80]})
                    continue
                k = _proxy_key(d)
                if k in seen:
                    dup += 1
                    continue
                seen.add(k)
                px.append(_new_proxy(**d))
                added += 1
            if added:
                _save_proxies(px)
            return self._json({"ok": True, "added": added,
                               "dup": dup, "bad": bad})
        if self.path == "/api/proxies/update":
            req = self._body()
            px = _load_proxies()
            p = next((x for x in px if x["id"] == req.get("id")), None)
            if not p:
                return self._json({"error": "代理不存在"}, 404)
            for k in ("note", "host", "port", "username",
                      "password", "scheme"):
                if k in req:
                    p[k] = req[k]
            if "banned" in req:
                p["banned"] = bool(req["banned"])
                if not p["banned"]:
                    p["ban_reason"] = []
            _save_proxies(px)
            return self._json({"ok": True})
        if self.path == "/api/proxies/delete":
            req = self._body()
            ids = set(req.get("ids") or [])
            px = _load_proxies()
            keep = [p for p in px if p["id"] not in ids]
            _save_proxies(keep)
            return self._json({"ok": True,
                               "deleted": len(px) - len(keep)})
        if self.path == "/api/proxies/check":
            req = self._body()
            ids = set(req.get("ids") or [])
            px = _load_proxies()
            todo = [p for p in px if not ids or p["id"] in ids]
            if not todo:
                return self._json({"error": "没有要测的代理"})
            if len(todo) > 500:
                return self._json({"error": "单次最多测 500 条"}, 400)
            up = _upstream()
            results = {}

            def _one(p):
                ok, ms, ip, err = _socks5_check(p, upstream=up)
                results[p["id"]] = {"ok": ok, "ms": ms,
                                    "exit_ip": ip, "err": err}
                p["alive"] = ok
                p["latency_ms"] = ms
                p["exit_ip"] = ip
                p["checked_at"] = _now()

            with ThreadPoolExecutor(max_workers=16) as ex:
                list(ex.map(_one, todo))
            _save_proxies(px)
            return self._json({"ok": True, "tested": len(todo),
                               "passed": sum(1 for r in results.values()
                                             if r["ok"]),
                               "results": results})
        if self.path == "/api/settings":
            req = self._body()
            s = _settings()
            if "upstream_proxy" in req:
                raw = (req.get("upstream_proxy") or "").strip()
                if raw:
                    test = raw if "://" in raw else "http://" + raw
                    d, err = _parse_proxy_line(test, "http")
                    if err:
                        return self._json(
                            {"error": f"上级代理格式无法解析: {err}"}, 400)
                s["upstream_proxy"] = raw
            for k in ("namegen_enabled", "namegen_url",
                      "namegen_model", "namegen_key",
                      "namegen_prompt",
                      "pace_step_min", "pace_step_max",
                      "pace_type_min", "pace_type_max",
                      "pace_load_ms", "proxy_cool_min",
                      "oauth_ttl_min", "open_workers", "open_env",
                      "step_watch", "step_gen", "step_email",
                      "step_code", "step_password", "step_profile",
                      "cpa_url", "cpa_key", "cpa_autopush"):
                if k in req:
                    s[k] = req[k]
            _save_settings(s)
            return self._json({"ok": True})
        if self.path == "/api/settings/namegen-models":
            # GET <base>/models —— OpenAI 兼容接口的模型列表。
            # 可用表单当前值测, 不必先保存 (url/key 可从请求体覆盖)
            req = self._body()
            s = _settings()
            url = (req.get("url") or s.get("namegen_url") or "") \
                .strip().rstrip("/")
            key = req.get("key") or s.get("namegen_key") or ""
            if url.endswith("/chat/completions"):
                url = url[:-len("/chat/completions")]
            if not url:
                return self._json({"error": "先填接口地址"})
            hdrs = {"Authorization": "Bearer " + key} if key else None
            up = _upstream() if url.startswith("https://") else None
            try:
                body = _https_get(url + "/models", up, 20,
                                  headers=hdrs)
                j = json.loads(body.decode(errors="ignore"))
                models = sorted(m["id"] for m in j.get("data") or []
                                if m.get("id"))
                if not models and isinstance(j.get("models"), list):
                    models = sorted(str(m) for m in j["models"])
                return self._json({"ok": True, "models": models,
                                   "count": len(models)})
            except Exception as e:
                return self._json({"error": "拉模型列表失败: "
                                            + str(e)[:120]})
        if self.path == "/api/settings/test-namegen":
            # 用一条样例邮箱实测生成链路
            req = self._body()
            em = (req.get("email") or "falcaonatalia618@gmail.com")
            msgs = []
            r = _gen_profile(em, lambda m: msgs.append(m))
            if not r:
                return self._json({"error": "未生成 —— "
                                   + (msgs[-1] if msgs else
                                      "检查是否启用/填了接口地址")})
            return self._json({"ok": True, "name": r[0],
                               "age": r[1], "logs": msgs})
        if self.path == "/api/accounts/import":
            try:
                req = self._body()
            except Exception:
                return self._json({"error": "请求体不是 JSON"}, 400)
            text = req.get("text") or ""
            accs = _load_accounts()
            seen = {a["email"] for a in accs}
            added, dup, bad = 0, 0, []
            for i, line in enumerate(text.splitlines(), 1):
                d, err = _parse_account_line(line)
                if err in ("empty", "comment"):
                    continue
                if err:
                    bad.append({"line": i, "err": err,
                                "raw": line.strip()[:80]})
                    continue
                if d["email"] in seen:
                    dup += 1
                    continue
                seen.add(d["email"])
                accs.append(_new_account(**d))
                added += 1
            if added:
                _save_accounts(accs)
            return self._json({"ok": True, "added": added,
                               "dup": dup, "bad": bad})
        if self.path == "/api/accounts/archive":
            # 归档 = 关/删 Roxy 窗口释放配额 + 停接码监听, 记录留着。
            # 代理绑定保留 —— 恢复开窗还是同一条 IP。
            req = self._body()
            ids = set(req.get("ids") or [])
            accs = _load_accounts()
            n, werr = 0, []
            for a in accs:
                if a["id"] not in ids or a.get("archived"):
                    continue
                a["archived"] = True
                a["archived_at"] = _now()
                w = MAIL_WATCH.pop(a["id"], None)
                if w:
                    w["stop"] = True
                PROF_WATCH.pop(a["id"], None)
                if a.get("win"):
                    e = _roxy_delete_window(a["win"])
                    a["win"] = None
                    if e:
                        werr.append(f"{a['email']}: {e}")
                n += 1
            _save_accounts(accs)
            return self._json({"ok": True, "archived": n,
                               "window_errors": werr})
        if self.path == "/api/accounts/close-win":
            # 批量关浏览器进程 —— 窗口配置/代理绑定/记录都不动,
            # 下次开窗原窗秒起。跟「归档」(删窗) 是两回事。
            req = self._body()
            ids = set(req.get("ids") or [])
            ok, failed = 0, {}
            for a in _load_accounts():
                if a["id"] not in ids or not a.get("win"):
                    continue
                e = _roxy_close_window(a["win"])
                if e:
                    failed[a["email"]] = e
                else:
                    ok += 1
            return self._json({"ok": ok, "failed": failed or None})
        if self.path == "/api/accounts/restore":
            req = self._body()
            ids = set(req.get("ids") or [])
            accs = _load_accounts()
            n = 0
            for a in accs:
                if a["id"] in ids and a.get("archived"):
                    a["archived"] = False
                    a.pop("archived_at", None)
                    n += 1
            _save_accounts(accs)
            return self._json({"ok": True, "restored": n})
        if self.path == "/api/accounts/delete":
            req = self._body()
            ids = set(req.get("ids") or [])
            accs = _load_accounts()
            doomed = [a for a in accs if a["id"] in ids]
            px = _load_proxies()
            win_ok, win_err = 0, []
            for a in doomed:
                p = next((x for x in px
                          if x["id"] == a.get("proxy_id")), None)
                if p:
                    _unbind_proxy(p, a["email"])
                # 联动删 Roxy 窗口 (账号绑过 auto- 窗的 dirId)
                if a.get("win"):
                    e = _roxy_delete_window(a["win"])
                    if e:
                        win_err.append(f"{a['email']}: {e}")
                    else:
                        win_ok += 1
            _save_proxies(px)
            keep = [a for a in accs if a["id"] not in ids]
            _save_accounts(keep)
            return self._json({"ok": True,
                               "deleted": len(accs) - len(keep),
                               "windows_deleted": win_ok,
                               "window_errors": win_err})
        if self.path == "/api/accounts/update":
            req = self._body()
            accs = _load_accounts()
            a = next((x for x in accs if x["id"] == req.get("id")), None)
            if not a:
                return self._json({"error": "账号不存在"}, 404)
            for k in ("note", "password", "extra", "status",
                      "mail_url", "totp"):
                if k in req:
                    a[k] = req[k]
            _save_accounts(accs)
            return self._json({"ok": True})
        if self.path == "/api/accounts/unbind":
            req = self._body()
            accs = _load_accounts()
            a = next((x for x in accs if x["id"] == req.get("id")), None)
            if not a:
                return self._json({"error": "账号不存在"}, 404)
            px = _load_proxies()
            p = next((x for x in px if x["id"] == a.get("proxy_id")),
                     None)
            if p:
                _unbind_proxy(p, a["email"])
                _save_proxies(px)
            a["proxy_id"] = None
            _save_accounts(accs)
            return self._json({"ok": True})
        if self.path == "/api/accounts/bind-proxy":
            """手动绑代理: {id, proxy_id}。已绑别条则自动换绑;
            封禁的拒绑, 满载/冷却由用户显式选择覆盖。"""
            req = self._body()
            accs = _load_accounts()
            a = next((x for x in accs if x["id"] == req.get("id")),
                     None)
            if not a:
                return self._json({"error": "账号不存在"}, 404)
            px = _load_proxies()
            p = next((x for x in px
                      if x["id"] == req.get("proxy_id")), None)
            if not p:
                return self._json({"error": "代理不存在"}, 404)
            if p.get("banned"):
                return self._json({"error": "该代理已封禁"})
            old = next((x for x in px
                        if x["id"] == a.get("proxy_id")), None)
            rebound = None
            if old and old["id"] != p["id"]:
                _unbind_proxy(old, a["email"])
                rebound = (f"{old['scheme']}://"
                           f"{old['host']}:{old['port']}")
            _bind_proxy(p, a["email"])
            a["proxy_id"] = p["id"]
            _save_proxies(px)
            _save_accounts(accs)
            return self._json(
                {"ok": True,
                 "proxy": f"{p['scheme']}://{p['host']}:{p['port']}",
                 "rebound": rebound,
                 "load": _bound_count(p)})
        if self.path == "/api/accounts/open":
            req = self._body()
            if OPEN_JOB["running"]:
                return self._json({"error": "已有开窗任务在跑"}, 409)
            ids = set(req.get("ids") or [])
            accs = [a for a in _load_accounts()
                    if (not ids or a["id"] in ids)
                    and not a.get("archived")]
            if not accs:
                return self._json({"error": "没有要开的账号"})
            if len(accs) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(
                target=_open_worker, args=(accs,),
                daemon=True).start()
            return self._json({"ok": True, "count": len(accs)})
        if self.path == "/api/accounts/open/stop":
            OPEN_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/mail-codes/start":
            req = self._body()
            a = next((x for x in _load_accounts()
                      if x["id"] == req.get("id")), None)
            if not a or not a.get("mail_url"):
                return self._json({"error": "该账号没有接码链接"}, 400)
            _mail_watch_start(a)
            return self._json({"ok": True})
        if self.path == "/api/mail-codes/stop":
            req = self._body()
            aid = req.get("id")
            w = MAIL_WATCH.get(aid)
            if w:
                w["stop"] = True
                w["hidden"] = True    # 点 X = 不想再看到它
            PROF_WATCH.pop(aid, None)
            return self._json({"ok": True})
        if self.path == "/api/accounts/reg-mark":
            # 人工确认注册结果 —— 开窗 worker 轮询这个放行 (真串行)。
            # done: reg=yes 已注册;  skip: reg_skip 本次放行不标记注册
            req = self._body()
            ids = req.get("ids") or []
            mark = req.get("mark")
            if mark not in ("done", "skip"):
                return self._json({"error": "mark 须 done|skip"}, 400)
            accs = _load_accounts()
            n = 0
            for a in accs:
                if a["id"] in ids:
                    if mark == "done":
                        a["reg"] = "yes"
                        a["reg_at"] = _now()
                    else:
                        a["reg_skip"] = True
                    n += 1
            _save_accounts(accs)
            return self._json({"ok": True, "marked": n})
        if self.path == "/api/accounts/pat-check/stop":
            PAT_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/mother":
            req = self._body()
            s = _settings()
            s["mother_window"] = (req.get("mother_window")
                                  or "").strip()
            s["mother_workspace"] = (req.get("mother_workspace")
                                     or "").strip()
            s["mother_workspace_name"] = \
                (req.get("mother_workspace_name") or "").strip()
            _save_settings(s)
            return self._json({"ok": True})
        if self.path == "/api/accounts/pat-check":
            req = self._body()
            if PAT_JOB["running"]:
                return self._json({"error": "PAT 检验在跑"}, 409)
            ids = [i for i in (req.get("ids") or [])]
            if not ids:
                return self._json({"error": "没选账号"})
            if len(ids) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(target=_pat_worker, args=(ids,),
                             daemon=True).start()
            return self._json({"ok": True, "count": len(ids)})
        if self.path == "/api/accounts/ios-reg/stop":
            IOS_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/accounts/ios-reg":
            req = self._body()
            if IOS_JOB["running"]:
                return self._json({"error": "iOS 注册在跑"}, 409)
            ids = [i for i in (req.get("ids") or [])]
            if not ids:
                return self._json({"error": "没选账号"})
            if len(ids) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(target=_ios_reg_worker, args=(ids,),
                             daemon=True).start()
            return self._json({"ok": True, "count": len(ids)})
        if self.path == "/api/accounts/proto-pat/stop":
            PROTO_PAT_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/accounts/proto-pat":
            req = self._body()
            if PROTO_PAT_JOB["running"]:
                return self._json({"error": "协议PAT 在跑"}, 409)
            ids = [i for i in (req.get("ids") or [])]
            if not ids:
                return self._json({"error": "没选账号"})
            if len(ids) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(target=_proto_pat_worker,
                             args=(ids,), daemon=True).start()
            return self._json({"ok": True, "count": len(ids)})
        if self.path == "/api/mothers/add":
            req = self._body()
            raw = req.get("names") or req.get("name") or ""
            names = [x.strip() for x in raw.splitlines()
                     if x.strip()]
            if not names:
                return self._json({"error": "没有要导入的窗口名"})
            ms = _load_mothers()
            seen = {m["name"] for m in ms}
            pat = (_settings().get("mother_window") or "").strip()
            added, dup, skipped = 0, 0, 0
            for n in names:
                if n == pat:
                    skipped += 1
                    continue
                if n in seen:
                    dup += 1
                    continue
                seen.add(n)
                ms.append({"name": n, "ws": "", "ws_name": "",
                           "added_at": _now()})
                added += 1
            _save_mothers(ms)
            return self._json({"ok": True, "added": added,
                               "dup": dup, "skipped_pat": skipped})
        if self.path == "/api/mothers/delete":
            req = self._body()
            names = set(req.get("names") or [])
            ms = _load_mothers()
            keep = [m for m in ms if m["name"] not in names]
            _save_mothers(keep)
            return self._json({"ok": True,
                               "deleted": len(ms) - len(keep)})
        if self.path == "/api/mothers/set-ws":
            req = self._body()
            ms = _load_mothers()
            m = next((x for x in ms
                      if x["name"] == req.get("name")), None)
            if not m:
                return self._json({"error": "母号不存在"}, 404)
            m["ws"] = (req.get("ws") or "").strip()
            m["ws_name"] = (req.get("ws_name") or "").strip()
            _save_mothers(ms)
            return self._json({"ok": True})
        if self.path == "/api/mothers/billing":
            """批量查母号空间账单: 席位价/续费时间/当前席位数。"""
            req = self._body()
            names = req.get("names") or []
            if not names:
                return self._json({"error": "没选母号"})
            mothers = _load_mothers()
            out = {}
            changed = False
            for name in names:
                m = next((x for x in mothers
                          if x.get("name") == name), None)
                if not m:
                    out[name] = {"error": "母号不存在"}
                    continue
                r, err = _mother_billing(name, m.get("ws") or "")
                if err:
                    out[name] = {"error": err}
                    continue
                m["bill"] = r
                if not m.get("ws") and r.get("ws_id"):
                    m["ws"] = r["ws_id"]
                    m["ws_name"] = r.get("ws_name") or ""
                changed = True
                out[name] = r
            if changed:
                _save_mothers(mothers)
            return self._json({"ok": True, "map": out})
        if self.path == "/api/accounts/join-space":
            req = self._body()
            if JOIN_JOB["running"]:
                return self._json({"error": "加入空间任务在跑"}, 409)
            ids = [i for i in (req.get("ids") or [])]
            mname = (req.get("mother") or "").strip()
            seat = (req.get("seat") or "prolite").strip()
            if seat not in ("default", "prolite"):
                seat = "prolite"
            if not ids:
                return self._json({"error": "没选账号"})
            if not mname:
                return self._json({"error": "没选空间母号"})
            if len(ids) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(target=_join_worker,
                             args=(ids, mname, seat), daemon=True).start()
            return self._json({"ok": True, "count": len(ids)})
        if self.path == "/api/accounts/join/stop":
            JOIN_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/accounts/ws-list":
            # 拉每个号实际所在空间 (开窗 evaluate, 存 a.ws_list)
            req = self._body()
            ids = req.get("ids") or []
            out = {}
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                for aid in ids[:20]:
                    a = next((x for x in _load_accounts()
                              if x["id"] == aid), None)
                    if not a:
                        continue
                    p = next((x for x in _load_proxies()
                              if x["id"] == a.get("proxy_id")), None)
                    if not p or p.get("banned"):
                        out[aid] = {"error": "没绑代理"}
                        continue
                    try:
                        dir_id, cws, err = _roxy_open_for(
                            a["email"], p)
                        if err or not cws:
                            out[aid] = {"error": err or "开窗失败"}
                            continue
                        a["win"] = dir_id
                        cbr = pw.chromium.connect_over_cdp(cws)
                        try:
                            cpg = _find_cgpt_page(cbr)
                            if not cpg:
                                cpg = cbr.contexts[0].new_page()
                                cpg.goto(
                                    TARGET_URL,
                                    wait_until="domcontentloaded",
                                    timeout=60000)
                                cpg.wait_for_timeout(3000)
                            lst = cpg.evaluate(_WS_LIST_JS)
                            if lst.get("error"):
                                out[aid] = {"error": lst["error"]}
                                continue
                            ws = lst.get("workspaces") or []
                            a["ws_list"] = ws
                            # 实况里已不在记录的空间 → 标已退出
                            # (被母号移除/别处退的也能对上)
                            if a.get("space_ws") and not any(
                                    w.get("id") == a["space_ws"]
                                    for w in ws):
                                a["space_left"] = {
                                    "ws": a["space_ws"],
                                    "name": a.get("space") or "",
                                    "at": _now(), "by": "gone"}
                                for k in ("space", "space_ws",
                                          "space_mother", "space_at",
                                          "space_seat"):
                                    a.pop(k, None)
                            out[aid] = {"list": ws}
                        finally:
                            try:
                                cbr.close()
                            except Exception:
                                pass
                    except Exception as e:
                        out[aid] = {"error": str(e)[:100]}
                    finally:
                        accs_all = _load_accounts()
                        for x in accs_all:
                            if x["id"] == aid:
                                x.clear(); x.update(a)
                                break
                        _save_accounts(accs_all)
            return self._json({"ok": True, "map": out})
        if self.path == "/api/accounts/leave":
            req = self._body()
            if LEAVE_JOB["running"]:
                return self._json({"error": "退出空间任务在跑"}, 409)
            ids = [i for i in (req.get("ids") or [])]
            ws_name = (req.get("ws_name") or "").strip()
            pairs = req.get("pairs") or {}
            if not ids:
                return self._json({"error": "没选账号"})
            if not ws_name and not pairs:
                return self._json({"error": "没指定要退出的空间"}, 400)
            if len(ids) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(
                target=_leave_worker,
                args=(ids, ws_name or None, pairs or None),
                daemon=True).start()
            return self._json({"ok": True, "count": len(ids)})
        if self.path == "/api/accounts/leave/stop":
            LEAVE_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/accounts/cpa-oauth":
            req = self._body()
            if CPA_JOB["running"]:
                return self._json({"error": "CPA OAuth 任务在跑"}, 409)
            ids = [i for i in (req.get("ids") or [])]
            if not ids:
                return self._json({"error": "没选账号"})
            if len(ids) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(target=_cpa_worker, args=(ids,),
                             daemon=True).start()
            return self._json({"ok": True, "count": len(ids)})
        if self.path == "/api/accounts/cpa/stop":
            CPA_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/accounts/oauth-callback":
            # 手动兜底: 贴完整回调链接 (自动按 state 对账号)
            # 或裸 code (仅当只有一个账号在等回调时)
            req = self._body()
            raw = (req.get("url") or "").strip()
            if not raw:
                return self._json({"error": "贴回调链接"})
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(raw).query)
            code = (qs.get("code") or [""])[0]
            state = (qs.get("state") or [""])[0]
            if not code:
                code = raw.split("code=")[-1].split("&")[0] \
                    if "code=" in raw else raw
            accs = _load_accounts()
            _oauth_expire(accs)   # 先清过期的 —— 死链接不许再换
            pend = [x for x in accs if x.get("oauth_verifier")]
            a = None
            if state:
                a = next((x for x in pend
                          if x.get("oauth_state") == state), None)
            if not a and len(pend) == 1:
                a = pend[0]
            if not a and req.get("id"):
                a = next((x for x in accs
                          if x["id"] == req["id"]), None)
            if not a:
                return self._json({"error":
                    "对不上账号 (state 匹配失败 —— 可能已过期,"
                    " 重跑OAuth授权)"
                    if state else
                    "多个账号在等回调, 请贴带 state= 的完整链接"
                    if len(pend) > 1 else
                    "没有在等回调的账号 (先跑OAuth授权,"
                    " 或链接已过期需重跑)"})
            if not a.get("oauth_verifier"):
                return self._json(
                    {"error": "该账号没有进行中的 OAuth,"
                     " 重跑🔗OAuth授权"})
            if not code:
                return self._json({"error": "链接里没有 code="})
            px = _load_proxies()
            p = next((x for x in px
                      if x["id"] == a.get("proxy_id")), None)
            if not p:
                return self._json({"error": "账号没绑代理"})
            j, err = _oauth_exchange(p, code,
                                     a["oauth_verifier"])
            if err:
                return self._json(
                    {"error": "换token失败: " + err})
            cred = _oauth_cred(j, _proxy_url(p, "url"))
            a["cred"] = cred
            a["cred_file"] = _cred_name(cred)
            a["cred_at"] = _now()
            a["cpa"] = "ready"
            a.pop("oauth_url", None)
            a.pop("oauth_state", None)
            a.pop("oauth_verifier", None)
            _save_accounts(accs)
            return self._json({"ok": True, "email": a["email"],
                               "cred_file": a["cred_file"]})
        if self.path == "/api/accounts/cpa-push":
            req = self._body()
            ids = req.get("ids") or []
            if not ids:
                return self._json({"error": "没选账号"})
            accs = _load_accounts()
            ok, failed = 0, {}
            for a in accs:
                if a["id"] not in ids:
                    continue
                cred = a.get("cred")
                if not cred:
                    failed[a["email"]] = "没有凭证 (先跑OAuth)"
                    continue
                err = _cpa_push_cred(
                    a.get("cred_file") or _cred_name(cred), cred)
                if err:
                    failed[a["email"]] = err
                else:
                    a["cpa"] = "yes"
                    a["cpa_at"] = _now()
                    ok += 1
            _save_accounts(accs)
            return self._json({"ok": ok,
                               "failed": failed or None})
        # ---------- Google 账号 (antigravity) ----------
        if self.path == "/api/g/proxies/import":
            try:
                req = self._body()
            except Exception:
                return self._json({"error": "请求体不是 JSON"}, 400)
            text = req.get("text") or ""
            default_scheme = req.get("scheme") or "socks5"
            px = _load_gproxies()
            seen = {_proxy_key(p) for p in px}
            added, dup, bad = 0, 0, []
            for i, line in enumerate(text.splitlines(), 1):
                d, err = _parse_proxy_line(line, default_scheme)
                if err in ("empty", "comment"):
                    continue
                if err:
                    bad.append({"line": i, "err": err,
                                "raw": line.strip()[:80]})
                    continue
                k = _proxy_key(d)
                if k in seen:
                    dup += 1
                    continue
                seen.add(k)
                px.append(_new_proxy(**d))
                added += 1
            if added:
                _save_gproxies(px)
            return self._json({"ok": True, "added": added,
                               "dup": dup, "bad": bad})
        if self.path == "/api/g/proxies/update":
            req = self._body()
            px = _load_gproxies()
            p = next((x for x in px if x["id"] == req.get("id")), None)
            if not p:
                return self._json({"error": "代理不存在"}, 404)
            for k in ("note", "host", "port", "username",
                      "password", "scheme"):
                if k in req:
                    p[k] = req[k]
            if "banned" in req:
                p["banned"] = bool(req["banned"])
                if not p["banned"]:
                    p["ban_reason"] = []
            _save_gproxies(px)
            return self._json({"ok": True})
        if self.path == "/api/g/proxies/delete":
            req = self._body()
            ids = set(req.get("ids") or [])
            px = _load_gproxies()
            keep = [p for p in px if p["id"] not in ids]
            _save_gproxies(keep)
            return self._json({"ok": True,
                               "deleted": len(px) - len(keep)})
        if self.path == "/api/g/proxies/check":
            req = self._body()
            ids = set(req.get("ids") or [])
            px = _load_gproxies()
            todo = [p for p in px if not ids or p["id"] in ids]
            if not todo:
                return self._json({"error": "没有要测的代理"})
            if len(todo) > 500:
                return self._json({"error": "单次最多测 500 条"}, 400)
            up = _gupstream()
            results = {}

            def _gone(p):
                ok, ms, ip, err = _socks5_check(p, upstream=up)
                results[p["id"]] = {"ok": ok, "ms": ms,
                                    "exit_ip": ip, "err": err}
                p["alive"] = ok
                p["latency_ms"] = ms
                p["exit_ip"] = ip
                p["checked_at"] = _now()

            with ThreadPoolExecutor(max_workers=16) as ex:
                list(ex.map(_gone, todo))
            _save_gproxies(px)
            return self._json({"ok": True, "tested": len(todo),
                               "passed": sum(1 for r in results.values()
                                             if r["ok"]),
                               "results": results})
        if self.path == "/api/g/settings":
            req = self._body()
            s = _gsettings()
            if "upstream_proxy" in req:
                raw = (req.get("upstream_proxy") or "").strip()
                if raw:
                    test = raw if "://" in raw else "http://" + raw
                    d, err = _parse_proxy_line(test, "http")
                    if err:
                        return self._json(
                            {"error": f"上级代理格式无法解析: {err}"},
                            400)
                s["upstream_proxy"] = raw
            for k in ("proxy_cool_min", "oauth_ttl_min",
                      "cpa_url", "cpa_key", "cpa_autopush",
                      "open_env"):
                if k in req:
                    s[k] = req[k]
            _save_gsettings(s)
            return self._json({"ok": True})
        if self.path == "/api/g/accounts/import":
            try:
                req = self._body()
            except Exception:
                return self._json({"error": "请求体不是 JSON"}, 400)
            text = req.get("text") or ""
            accs = _load_gaccounts()
            seen = {a["email"] for a in accs}
            added, dup, bad = 0, 0, []
            for i, line in enumerate(text.splitlines(), 1):
                d, err = _parse_account_line(line)
                if err in ("empty", "comment"):
                    continue
                if err:
                    bad.append({"line": i, "err": err,
                                "raw": line.strip()[:80]})
                    continue
                if d["email"] in seen:
                    dup += 1
                    continue
                seen.add(d["email"])
                accs.append(_new_gaccount(**d))
                added += 1
            if added:
                _save_gaccounts(accs)
            return self._json({"ok": True, "added": added,
                               "dup": dup, "bad": bad})
        if self.path == "/api/g/accounts/archive":
            # 归档 = 关/删 gauto- 窗口释放配额, 记录+凭证+代理绑定全留
            req = self._body()
            ids = set(req.get("ids") or [])
            accs = _load_gaccounts()
            n, werr = 0, []
            for a in accs:
                if a["id"] not in ids or a.get("archived"):
                    continue
                a["archived"] = True
                a["archived_at"] = _now()
                if a.get("win"):
                    e = _roxy_delete_window(a["win"])
                    a["win"] = None
                    if e:
                        werr.append(f"{a['email']}: {e}")
                n += 1
            _save_gaccounts(accs)
            return self._json({"ok": True, "archived": n,
                               "window_errors": werr})
        if self.path == "/api/g/accounts/close-win":
            # 批量关 gauto- 浏览器进程 —— 窗口配置留着不动
            req = self._body()
            ids = set(req.get("ids") or [])
            ok, failed = 0, {}
            for a in _load_gaccounts():
                if a["id"] not in ids or not a.get("win"):
                    continue
                e = _roxy_close_window(a["win"])
                if e:
                    failed[a["email"]] = e
                else:
                    ok += 1
            return self._json({"ok": ok, "failed": failed or None})
        if self.path == "/api/g/accounts/restore":
            req = self._body()
            ids = set(req.get("ids") or [])
            accs = _load_gaccounts()
            n = 0
            for a in accs:
                if a["id"] in ids and a.get("archived"):
                    a["archived"] = False
                    a.pop("archived_at", None)
                    n += 1
            _save_gaccounts(accs)
            return self._json({"ok": True, "restored": n})
        if self.path == "/api/g/accounts/delete":
            req = self._body()
            ids = set(req.get("ids") or [])
            accs = _load_gaccounts()
            doomed = [a for a in accs if a["id"] in ids]
            px = _load_gproxies()
            win_ok, win_err = 0, []
            for a in doomed:
                p = next((x for x in px
                          if x["id"] == a.get("proxy_id")), None)
                if p:
                    _unbind_proxy(p, a["email"], _gcool_secs())
                if a.get("win"):
                    e = _roxy_delete_window(a["win"])
                    if e:
                        win_err.append(f"{a['email']}: {e}")
                    else:
                        win_ok += 1
            _save_gproxies(px)
            keep = [a for a in accs if a["id"] not in ids]
            _save_gaccounts(keep)
            return self._json({"ok": True,
                               "deleted": len(accs) - len(keep),
                               "windows_deleted": win_ok,
                               "window_errors": win_err})
        if self.path == "/api/g/accounts/update":
            req = self._body()
            accs = _load_gaccounts()
            a = next((x for x in accs if x["id"] == req.get("id")),
                     None)
            if not a:
                return self._json({"error": "账号不存在"}, 404)
            for k in ("note", "password", "extra", "status",
                      "mail_url", "totp"):
                if k in req:
                    a[k] = req[k]
            _save_gaccounts(accs)
            return self._json({"ok": True})
        if self.path == "/api/g/accounts/unbind":
            req = self._body()
            accs = _load_gaccounts()
            a = next((x for x in accs if x["id"] == req.get("id")),
                     None)
            if not a:
                return self._json({"error": "账号不存在"}, 404)
            px = _load_gproxies()
            p = next((x for x in px
                      if x["id"] == a.get("proxy_id")), None)
            if p:
                _unbind_proxy(p, a["email"], _gcool_secs())
                _save_gproxies(px)
            a["proxy_id"] = None
            _save_gaccounts(accs)
            return self._json({"ok": True})
        if self.path == "/api/g/accounts/bind-proxy":
            req = self._body()
            accs = _load_gaccounts()
            a = next((x for x in accs if x["id"] == req.get("id")),
                     None)
            if not a:
                return self._json({"error": "账号不存在"}, 404)
            px = _load_gproxies()
            p = next((x for x in px
                      if x["id"] == req.get("proxy_id")), None)
            if not p:
                return self._json({"error": "代理不存在"}, 404)
            if p.get("banned"):
                return self._json({"error": "该代理已封禁"})
            old = next((x for x in px
                        if x["id"] == a.get("proxy_id")), None)
            rebound = None
            if old and old["id"] != p["id"]:
                _unbind_proxy(old, a["email"], _gcool_secs())
                rebound = (f"{old['scheme']}://"
                           f"{old['host']}:{old['port']}")
            _bind_proxy(p, a["email"], _gcool_secs())
            a["proxy_id"] = p["id"]
            _save_gproxies(px)
            _save_gaccounts(accs)
            return self._json(
                {"ok": True,
                 "proxy": f"{p['scheme']}://{p['host']}:{p['port']}",
                 "rebound": rebound,
                 "load": _bound_count(p)})
        if self.path == "/api/g/accounts/open":
            req = self._body()
            if GOPEN_JOB["running"]:
                return self._json({"error": "已有开窗任务在跑"}, 409)
            ids = set(req.get("ids") or [])
            accs = [a for a in _load_gaccounts()
                    if (not ids or a["id"] in ids)
                    and not a.get("archived")]
            if not accs:
                return self._json({"error": "没有要开的账号"})
            if len(accs) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(
                target=_gopen_worker, args=(accs,),
                daemon=True).start()
            return self._json({"ok": True, "count": len(accs)})
        if self.path == "/api/g/accounts/open/stop":
            GOPEN_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/g/oauth":
            req = self._body()
            if GOAUTH_JOB["running"]:
                return self._json({"error": "已有OAuth任务在跑"}, 409)
            ids = req.get("ids") or []
            if not ids:
                return self._json({"error": "没选账号"})
            threading.Thread(
                target=_goauth_worker, args=(ids,),
                daemon=True).start()
            return self._json({"ok": True, "count": len(ids)})
        if self.path == "/api/g/oauth/stop":
            GOAUTH_JOB["stop"] = True
            return self._json({"ok": True})
        if self.path == "/api/g/oauth-callback":
            req = self._body()
            u = (req.get("url") or "").strip()
            if not u:
                return self._json({"error": "贴回调 URL"})
            qs = urllib.parse.parse_qs(
                urllib.parse.urlparse(u).query)
            code = (qs.get("code") or [None])[0]
            state = (qs.get("state") or [""])[0]
            if not code:
                return self._json({"error": "URL 里没有 code"})
            accs = _load_gaccounts()
            _goauth_expire(accs)
            a = None
            if state:
                a = next((x for x in accs
                          if x.get("oauth_state") == state), None)
            if not a:
                pend = [x for x in accs if x.get("cpa") == "pending"]
                if len(pend) == 1:
                    a = pend[0]
            if not a:
                return self._json(
                    {"error": "没有匹配的待授权账号 (state 对不上,"
                              "可能已过期, 重跑OAuth授权)"}, 404)
            p = next((x for x in _load_gproxies()
                      if x["id"] == a.get("proxy_id")), None)
            if not p:
                return self._json(
                    {"error": "账号没绑代理 —— 全链同IP做不到"}, 400)
            logs = []
            err = _goauth_finish(
                p, a, code, lambda m: logs.append(m))
            _save_gaccounts(accs)
            if err:
                return self._json({"error": err, "logs": logs})
            return self._json({"ok": True, "email": a["email"],
                               "cred_file": a["cred_file"],
                               "logs": logs})
        if self.path == "/api/g/cpa-push":
            req = self._body()
            ids = req.get("ids") or []
            if not ids:
                return self._json({"error": "没选账号"})
            accs = _load_gaccounts()
            ok, failed = 0, {}
            for a in accs:
                if a["id"] not in ids:
                    continue
                cred = a.get("cred")
                if not cred:
                    failed[a["email"]] = "没有凭证 (先跑OAuth)"
                    continue
                err = _cpa_push_cred(
                    a.get("cred_file") or _gcred_name(cred), cred,
                    st=_gsettings())
                if err:
                    failed[a["email"]] = err
                else:
                    a["cpa"] = "yes"
                    a["cpa_at"] = _now()
                    ok += 1
            _save_gaccounts(accs)
            return self._json({"ok": ok,
                               "failed": failed or None})
        if self.path == "/api/settings/test-cpa":
            # 连通性: GET <cpa>/v8/management/credentials
            # (v8 不在退回 /v0/management/api-keys) ——
            # 顺带验证了管理 key 是否有效
            req = self._body()
            s = _settings()
            url = req.get("url") or s.get("cpa_url") or ""
            key = req.get("key") or s.get("cpa_key") or ""
            up = (_upstream() if str(url).startswith("https://")
                  else None)
            return self._json(_cpa_test(url, key, up))
        if self.path == "/api/g/settings/test-cpa":
            req = self._body()
            s = _gsettings()
            url = req.get("url") or s.get("cpa_url") or ""
            key = req.get("key") or s.get("cpa_key") or ""
            up = (_gupstream() if str(url).startswith("https://")
                  else None)
            return self._json(_cpa_test(url, key, up))
        if self.path == "/api/g/settings/test-upstream":
            up = _gupstream()
            if not up:
                return self._json({"error": "未配置上级代理"})
            t0 = time.time()
            try:
                s = _dial_via_upstream(up, "api.ipify.org", 443, 8)
                s.close()
                return self._json({"ok": True,
                                   "ms": int((time.time() - t0) * 1000),
                                   "scheme": up["scheme"]})
            except Exception as e:
                return self._json({"error": str(e)[:120]})
        if self.path == "/api/settings/test-upstream":
            # 经上级代理 CONNECT api.ipify.org:443 验证可达性
            up = _upstream()
            if not up:
                return self._json({"error": "未配置上级代理"})
            t0 = time.time()
            try:
                s = _dial_via_upstream(up, "api.ipify.org", 443, 8)
                s.close()
                return self._json({"ok": True,
                                   "ms": int((time.time() - t0) * 1000),
                                   "scheme": up["scheme"]})
            except Exception as e:
                return self._json({"error": str(e)[:120]})
        self.send_error(404)


if __name__ == "__main__":
    print(f"roxy-accounts @ http://127.0.0.1:{PORT}")
    try:
        import playwright  # noqa: F401
    except ImportError:
        print("!! playwright 不在这个解释器里 —— 请用 ./run.sh "
              "(.venv) 启动, 否则开窗/OAuth 全部失败")
    print(f"python: {sys.executable}")
    if _goauth_cb_server():
        print("google oauth callback @ http://127.0.0.1:51121")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
