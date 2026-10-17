#!/usr/bin/env python3
"""roxy-accounts — 自管理账号系统 (Roxy 浏览器自动化)
阶段1: 代理池 — socks5 静态代理自管理, 无下层同步。
导入/导出/测活/备注/封禁标记; bound[] 预留账号绑定。"""
import base64
import hashlib
import io
import json
import os
import re
import secrets
import socket
import ssl
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


def _dial_via_account_proxy(p, host, port, timeout):
    """本机 → (上级代理 →) 账号代理 → host:port。
    账号代理只有经上级链式才握手得通 (RST 直连)。"""
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


def _upstream():
    """settings.upstream_proxy -> _parse_proxy_line dict | None"""
    raw = (_settings().get("upstream_proxy") or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw          # 裸 host:port 默认 http
    d, _ = _parse_proxy_line(raw, "http")
    return d


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


def _roxy_env_for(email):
    return _ROXY_OS_POOL[zlib.crc32(email.encode())
                         % len(_ROXY_OS_POOL)]


def _roxy_open_for(email, proxy, kernel="Chrome"):
    """找到或创建 auto-<email> 窗口并绑定指定代理, 返回 (dirId, ws, err)。
    kernel 只在新建窗口时生效; 已有窗口沿用自己的内核。"""
    cfg = _roxy_cfg()
    name = f"auto-{email}"
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
        os_name, os_ver = _roxy_env_for(email)
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


def _roxy_goto_url(ws, url):
    """通过 CDP 让已开的 Roxy 窗口跳转到指定 url。"""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        br = pw.chromium.connect_over_cdp(ws)
        try:
            ctx = br.contexts[0] if br.contexts else None
            pg = (ctx.pages[0] if ctx and ctx.pages
                  else (ctx.new_page() if ctx else None))
            if pg is None:
                raise RuntimeError("拿不到窗口页面")
            pg.goto(url, wait_until="domcontentloaded", timeout=60000)
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
    password, mail_url, extra = "", "", ""

    def _classify(tok):
        nonlocal password, mail_url, extra
        if re.match(r"^https?://", tok, re.I) and not mail_url:
            mail_url = tok
        elif not password:
            password = tok
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
            "mail_url": mail_url, "extra": extra}, None


def _new_account(email, password, mail_url="", extra=""):
    return {"id": "ac_" + uuid.uuid4().hex[:10],
            "email": email, "password": password,
            "mail_url": mail_url, "extra": extra,
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


def _touch_cool(p, email):
    """账号取用/释放过这条代理 -> 对其他账号进入冷却期。
    同一账号 (bound 里 / 触发冷却的) 豁免。"""
    p["cool_email"] = email
    p["cool_until"] = time.strftime(
        "%Y-%m-%dT%H:%M:%S",
        time.localtime(time.time() + _cool_secs()))


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


def _pick_proxy(px, email=None, limit=PICK_LIMIT):
    """未封禁 + 绑定<limit + 非冷却(对 email);
    排序: 绑定数 -> 已知失效沉底 -> 最久未用。"""
    cands = [p for p in px if not p.get("banned")
             and _bound_count(p) < limit]
    avail = [p for p in cands if not _cooling(p, email)]
    PICK_LAST["cooled"] = len(cands) - len(avail)
    avail.sort(key=lambda p: (_bound_count(p),
                              p.get("alive") is False,
                              p.get("last_used") or "1970-01-01"))
    return avail[0] if avail else None


def _bind_proxy(p, email):
    bound = p.setdefault("bound", [])
    if email not in bound:
        bound.append(email)
    p["last_used"] = _now()
    _touch_cool(p, email)


def _unbind_proxy(p, email):
    bound = p.get("bound") or []
    if email in bound:
        bound.remove(email)
        _touch_cool(p, email)
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


def _chatgpt_goto(ws):
    """半自动: 只把窗口导航到 chatgpt.com 就交还人工。"""
    from playwright.sync_api import sync_playwright
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


def _chatgpt_code_step(ws, a, log, upstream, should_stop=None):
    """半自动·自动填码: 等验证码框 -> 轮询接码接口取新码 -> 填码提交。
    创建密码页留给人工; 人工若先一步越过码页则自动退出。
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
            # 等验证码框 —— 中途可能出现创建密码页 (人工), 或人工
            # 直接越过码页; 最长等 10 分钟
            deadline = time.time() + 600
            saw_code = False
            while time.time() < deadline:
                if stopped():
                    return "stopped"
                try:
                    url = pg.url or ""
                    cb = pg.query_selector(CODE_INPUT)
                    if cb and cb.is_visible():
                        saw_code = True
                        break
                    if not pg.query_selector(_PWD):
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


def _chatgpt_login(ws, a, log, upstream, should_stop=None):
    """开窗后: Log in -> 填邮箱 -> Continue -> 等码 -> 填码 -> Continue
    -> (新号) about-you 填姓名年龄 -> Continue。返回 ok|ok_new|no_mail|stopped|err。"""
    import random
    from playwright.sync_api import sync_playwright
    email = a["email"]

    def stopped():
        return bool(should_stop and should_stop())

    # 拟人节奏 —— 可在设置页配置, 默认步骤 2-6s / 击键 90-240ms
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
            # 1-3) 点 Log in -> 等邮箱框 -> 拟人填邮箱 (与半自动共用)
            err = _email_fill_step(pg, email, log,
                                   hdelay, tdelay, stopped)
            if err:
                return err
            # 3.5) 提交前记旧码基线 —— 供应商接码接口有缓存滞后,
            # 新邮件落地前会再把上一次的旧码返回一阵, 得排除
            stale = set()
            if a.get("mail_url"):
                try:
                    c0, e0 = _mail_code_once(a["mail_url"], upstream)
                    if e0 == "dead":
                        log("  ✗ 邮箱账号不可用 (602) —— 放弃")
                        return "email_dead"
                    if c0:
                        stale.add(c0)
                except Exception:
                    pass
            # 4) 真实点击 Continue (JS click 会被忽略)
            if not _real_continue(pg):
                return "提交按钮点不动"
            log("  已提交邮箱, 等验证码页 ...")
            # 5) 等验证码框或创建密码框 (新号可能先让设密码)
            _PWD_INPUT = "input[name=new-password]"
            try:
                pg.wait_for_selector(
                    CODE_INPUT + "," + _PWD_INPUT, timeout=60000)
            except Exception:
                if _looks_verify(pg):
                    log("  ⚠ 人机验证 —— 请手动完成后继续等码")
                    pg.wait_for_selector(
                        CODE_INPUT + "," + _PWD_INPUT,
                        timeout=120000)
                else:
                    return "没等到验证码输入框: " \
                        + (pg.url or "")[:60] + " " \
                        + _page_text(pg)[:80]
            # 5.5) 创建密码页: 生成随机密码存账号 -> 提交 -> 再等码
            try:
                if pg.query_selector(_PWD_INPUT):
                    hdelay()
                    pwd = _gen_password()
                    a["password"] = pwd
                    pg.click(_PWD_INPUT)
                    pg.type(_PWD_INPUT, pwd,
                            delay=tdelay())
                    hdelay()
                    _real_continue(pg)
                    log("  遇到创建密码页 —— 随机密码已生成"
                        "(存账号), 已提交")
                    pg.wait_for_selector(CODE_INPUT,
                                         timeout=60000)
            except Exception as e:
                return "创建密码页处理失败: " + str(e)[:80]
            log("  验证码页就绪, 查接码接口 ...")
            if not a.get("mail_url"):
                log("  ⚠ 该账号没有接码链接 —— 请手动收码填入")
                return "no_mail"
            # 6) 取码→填码→提交; 页面报 Incorrect code 就排除已试码
            #    等供应商收进新邮件再重试; 后期点 Resend 触发新邮件
            tried = set(stale)
            passed = False
            for attempt in range(4):
                if stopped():
                    return "stopped"
                if attempt >= 2:
                    try:
                        pg.click('button:has-text("Resend")',
                                 timeout=3000)
                        log("  已点 Resend 触发新邮件")
                        pg.wait_for_timeout(3000)
                    except Exception:
                        pass
                code = _fetch_mail_code(
                    a["mail_url"], upstream, log,
                    timeout=240 if attempt == 0 else 150,
                    exclude=tried, should_stop=should_stop)
                if stopped():
                    return "stopped"
                if code == "dead":
                    log("  ✗ 邮箱账号不可用 (602) —— 放弃该账号")
                    return "email_dead"
                if not code:
                    log("  ✗ 接码超时 —— 请手动在窗口继续")
                    return "code_timeout"
                tried.add(code)
                log("  📨 收到验证码: %s" % code)
                hdelay()
                try:
                    boxes = [b for b in
                             pg.query_selector_all(CODE_INPUT)
                             if b.is_visible()]
                    if len(boxes) == 1:
                        boxes[0].click()
                        boxes[0].fill("")
                        boxes[0].type(code,
                                      delay=tdelay())
                    elif len(boxes) > 1:
                        for i, bx in enumerate(boxes[:len(code)]):
                            bx.click()
                            bx.fill("")
                            bx.type(code[i],
                                    delay=tdelay())
                    else:
                        pg.keyboard.type(code,
                                         delay=tdelay())
                    hdelay()
                    _real_continue(pg)
                    log("  验证码已提交")
                except Exception as e:
                    log("  ⚠ 自动填码失败, 请手动输入 %s: %s"
                        % (code, str(e)[:60]))
                    break
                # 等页面判定: 跳离验证码页 = 过; incorrect = 等新码
                for _ in range(20):
                    time.sleep(1)
                    try:
                        if "email-verification" not in (pg.url or ""):
                            passed = True
                            break
                        txt = _page_text(pg).lower()
                        if any(w in txt for w in
                               ("incorrect", "invalid", "expired")):
                            log("  ✗ 码被拒 (%s), 等新邮件进来 ..."
                                % code)
                            break
                    except Exception:
                        pass             # 正在跳转
                if passed:
                    break
            if not passed:
                log("  ⚠ 验证码反复被拒 —— 窗口留着, 请手动检查")
                return "code_rejected"
            # 7) about-you 资料页 (新注册才有): 姓名+年龄+Continue
            is_new = False
            saw_about = False
            deadline = time.time() + 90
            while time.time() < deadline:
                if stopped():
                    return "stopped"
                try:
                    # 密码页也可能在验证码之后才弹
                    if pg.query_selector("input[name=new-password]"):
                        pwd = _gen_password()
                        a["password"] = pwd
                        pg.click("input[name=new-password]")
                        pg.type("input[name=new-password]", pwd,
                                delay=tdelay())
                        hdelay()
                        _real_continue(pg)
                        log("  验证码后补建密码 —— "
                            "随机密码已存账号并提交")
                        continue
                    if pg.query_selector("input[name=name]"):
                        saw_about = True
                        # 姓名/年龄: extra 手动指定 > AI 生成 > 邮箱前缀
                        gen = _gen_profile(email, log)
                        name = (a.get("extra") or "").strip() \
                            or (gen[0] if gen else "") \
                            or re.sub(r"[^A-Za-z]", "",
                                      email.split("@")[0]) \
                                   .capitalize() or "User"
                        age = str(gen[1] if gen
                                  else random.randint(22, 38))
                        # 真实键盘输入 (fill 不产生 keydown/keyup)
                        r = _about_fill(pg, name, age,
                                        log, hdelay, tdelay)
                        if r == "need_human":
                            return "about_you_need_human"
                        if r != "ok":
                            return r
                        log("  资料页已填 (%s, %s)%s"
                            % (name, age, " ← AI生成" if gen else ""))
                        is_new = True
                        break
                    if "chatgpt.com" in (pg.url or ""):
                        break               # 已回主站 = 完成
                except Exception:
                    pass
                time.sleep(2)
            if saw_about and not is_new:
                return "about_you_timeout"   # 卡在资料页, 别报假成功
            return "ok_new" if is_new else "ok"
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
    let j = null;
    try { j = await r.json(); } catch (e) {}
    const d = (j && j.detail) || {};
    const code = d.code || (d.error && d.error.code)
        || (j && j.error && j.error.code) || null;
    const msg = d.message || (d.error && d.error.message)
        || (j && j.error && j.error.message) || '';
    return {status: r.status, code: code,
            msg: String(msg).slice(0, 200),
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
                            x.update(a)
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
        log("母号窗口 %s 已连, 目标空间 %s, 席位 %s"
            % (mname, ws_name, seat))
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
                r = mpg.evaluate(_INVITE_JS, {
                    "ws": ws_id, "emails": list(emails.values()),
                    "fid": str(uuid.uuid4()),
                    "sid": str(uuid.uuid4()),
                    "seat": seat})
                if r.get("status") == 401 \
                        or "token_expired" in (r.get("body") or ""):
                    log("  母号 token 过期, 刷新页面重取 (%d/3)"
                        % (att + 1))
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
            log("→ 批量邀请完成: 新发 %d 个, 已是成员 %d 个"
                % (len(emails) - len(already & set(emails.values())),
                   len(already & set(emails.values()))))
            # 逐个子号: 开窗 → 刷新 → 接受邀请
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
                            a["space"] = ws_name
                            a["space_ws"] = ws_id
                            a["space_mother"] = mname
                            a["space_seat"] = r.get("seat") or seat
                            a["space_at"] = _now()
                            _ws_list_add(
                                a, ws_id, ws_name,
                                "standard-user")
                            JOIN_JOB["results"][aid] = \
                                "已入 " + ws_name
                            log("✓ %s: 已入 %s" % (email, ws_name))
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
                            x.update(a)
                            break
                    _save_accounts(accs_all)
            try:
                mbr.close()
            except Exception:
                pass
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
                    p = next((x for x in _load_proxies()
                              if x["id"] == a.get("proxy_id")), None)
                    if not p or p.get("banned"):
                        LEAVE_JOB["results"][aid] = "没绑代理"
                        log("✗ %s: 没绑代理" % email)
                        continue
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
                        # 解析目标空间 id
                        target = (pairs or {}).get(aid)
                        live = []
                        if not target:
                            try:
                                lst = cpg.evaluate(_WS_LIST_JS)
                                live = lst.get("workspaces") or []
                            except Exception:
                                pass
                            if ws_name:
                                for w in live:
                                    if (w.get("name") or "") \
                                            == ws_name:
                                        target = w["id"]
                                        break
                                if not target and \
                                        (a.get("space") or "") \
                                        == ws_name:
                                    target = a.get("space_ws")
                        if not target:
                            LEAVE_JOB["results"][aid] = \
                                "不在该空间"
                            log("✗ %s: 不在空间 %s (实际在: %s)"
                                % (email, ws_name or "?",
                                   ", ".join(w.get("name")
                                             for w in live)
                                   or "无"))
                            continue
                        r = cpg.evaluate(_LEAVE_WS_JS, target)
                        code = r.get("code")
                        if r.get("status") == 200:
                            wsn = r.get("name") \
                                or ws_name or target[:8]
                            if a.get("space_ws") == target:
                                for k in ("space", "space_ws",
                                          "space_mother",
                                          "space_at",
                                          "space_seat"):
                                    a.pop(k, None)
                            if a.get("ws_id") == target:
                                a.pop("ws_id", None)
                            if a.get("ws_list"):
                                a["ws_list"] = [
                                    w for w in a["ws_list"]
                                    if w.get("id") != target]
                            LEAVE_JOB["results"][aid] = \
                                "已退 " + wsn
                            log("✓ %s: 已退出 %s" % (email, wsn))
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
                            x.update(a)
                            break
                    _save_accounts(accs_all)
    finally:
        LEAVE_JOB["running"] = False
        log("—— 退出空间结束 ——"
            + (" (手动停止)" if LEAVE_JOB["stop"] else ""))


def _roxy_delete_window(dir_id):
    """关+删一个 Roxy 窗口 (先 close 再 delete, dirIds 是数组)。
    返回 err|None —— 尽力而为, 调用方不因此中断。"""
    cfg = _roxy_cfg()
    _roxy_call("/browser/close",
               {"workspaceId": cfg["workspace_id"], "dirId": dir_id},
               timeout=30)
    r = _roxy_call("/browser/delete",
                   {"workspaceId": cfg["workspace_id"],
                    "dirIds": [dir_id]}, timeout=30)
    err = r.get("error")
    if err and "不存在" in err:
        return None          # 已经没了 = 目标达成, 不算失败
    return err


# ---------------- CPA 号池 (CLIProxyAPI) ----------------
def _cpa_call(method, path, body=None, timeout=15):
    """调 CPA 管理接口, 返回 (status, json|None, err)。
    需要设置页已配 cpa_url (+cpa_key)。"""
    s = _settings()
    base = (s.get("cpa_url") or "").strip().rstrip("/")
    if not base:
        return 0, None, "未配置 CPA 地址 (设置页)"
    if "://" not in base:
        base = "http://" + base
    key = (s.get("cpa_key") or "").strip()
    hdrs = {"Authorization": "Bearer " + key} if key else {}
    url = base + path
    up = _upstream() if url.startswith("https://") else None
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


def _cpa_push_cred(name, cred):
    """推凭证 JSON 入 CPA 池 (v8/v0 auth-files?name=, 原始 JSON body)。
    返回 err|None。"""
    q = "?name=" + urllib.parse.quote(name)
    st, j, err = _cpa_call(
        "POST", "/v8/management/auth-files" + q, cred, timeout=30)
    if st == 404:
        st, j, err = _cpa_call(
            "POST", "/v0/management/auth-files" + q, cred,
            timeout=30)
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


def _post_form_via(p, host, path, form, timeout=30):
    """经账号代理 p 发 x-www-form-urlencoded POST → https://host/path。
    链式: 本机→上级代理→账号代理→目标, token 交换与注册同 IP。
    返回 (status, body)。"""
    s = _dial_via_account_proxy(p, host, 443, timeout)
    s = ssl.create_default_context().wrap_socket(
        s, server_hostname=host)
    s.settimeout(timeout)
    try:
        s.sendall((
            "POST %s HTTP/1.1\r\nHost: %s\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Accept: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n"
            % (path, host, len(form))).encode() + form)
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
                if not a:
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
                    log("→ %s: OAuth 链接已生成" % email)
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
                        cpg = _find_cgpt_page(cbr)
                        if not cpg:
                            cpg = cbr.contexts[0].new_page()
                        cpg.goto(url, wait_until="domcontentloaded",
                                 timeout=60000)
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
                        deadline = time.time() + 300   # 5 分钟授权窗口
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
                            done = "手动停止" if CPA_JOB["stop"] \
                                else "等回调超时"
                            a["cpa"] = "pending"
                            CPA_JOB["results"][aid] = done
                            log("✗ %s: %s (授权页留在窗口里,"
                                " 可手动继续后重跑)" % (email, done))
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
                        CPA_JOB["results"][aid] = "凭证已生成"
                        log("✓ %s: rt/at 到手, 凭证 %s 已备好"
                            " —— 推送入池用「📤推入池」"
                            % (email, a["cred_file"]))
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
                            x.update(a)
                            break
                    _save_accounts(accs_all)
    finally:
        CPA_JOB["running"] = False
        log("—— OAuth 授权结束 ——"
            + (" (手动停止)" if CPA_JOB["stop"] else ""))


# ---------------- 开窗任务 ----------------
OPEN_JOB = {"running": False, "log": [], "results": {},
            "stop": False}
TARGET_URL = "https://chatgpt.com"


OPEN_WORKERS = 3          # 并行开窗/注册并发数 (每个窗口是一个真 Chromium)


def _open_worker(accs, semiauto=False, watch_code=False,
                 gen_profile=False, auto_email=False, auto_code=False,
                 auto_profile=False):
    """并行: 选代理 -> 绑定 -> Roxy 开窗 -> 跳 chatgpt.com (注册)
    semiauto=True 时定位到主站即停, 登录注册全程人工;
    watch_code/gen_profile/auto_email/auto_code/auto_profile
    是半自动可选附加项
    (接码监听 / AI资料 / 自动填邮箱 / 自动填码 / 自动填资料)。
    db_lock 保护代理选取/绑定和 JSON 落盘 —— 避免并发抢同一代理
    或互相覆盖写文件。"""
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
                    x.update(a)
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
            if semiauto:
                r = _chatgpt_goto(ws)
                if r == "ok":
                    a["status"] = "opened"
                    OPEN_JOB["results"][a["id"]] = "已定位, 请手动操作"
                    log(f"✓ {email}: 已开到 chatgpt.com "
                        f"(半自动, 请手动注册)")
                    if watch_code and _mail_watch_start(a):
                        log(f"  [{email}] 📨 接码监听已开 (10min)")
                    if gen_profile:
                        _prof_gen_start(a)
                        log(f"  [{email}] 🤖 资料生成中 …")
                    if auto_email:
                        r2 = _chatgpt_email_step(
                            ws, a, lambda m: log(f"  [{email}] {m}"),
                            should_stop=_stopped)
                        if r2 == "ok":
                            log(f"  [{email}] ✉ 自动输入邮箱完成")
                        else:
                            log(f"  [{email}] ✉ 自动输入邮箱失败: {r2}"
                                f" —— 请手动继续")
                    if auto_code:
                        r3 = _chatgpt_code_step(
                            ws, a, lambda m: log(f"  [{email}] {m}"),
                            _upstream(), should_stop=_stopped)
                        if r3 == "ok":
                            log(f"  [{email}] 🔢 验证码已提交"
                                f" —— 剩余步骤交给你")
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
                    if auto_profile and not a.get("email_dead"):
                        r4 = _chatgpt_profile_step(
                            ws, a, lambda m: log(f"  [{email}] {m}"),
                            should_stop=_stopped)
                        if r4 == "ok":
                            log(f"  [{email}] 📝 自动填资料完成"
                                f" —— 注册应已落地")
                        elif r4 == "ok_passed":
                            log(f"  [{email}] 资料页已被人工越过")
                        elif r4 != "stopped":
                            log(f"  [{email}] 📝 自动填资料失败: {r4}"
                                f" —— 请手动继续")
                else:
                    a["status"] = "login_failed"
                    OPEN_JOB["results"][a["id"]] = r
                    log(f"✗ {email}: 导航失败 — {r}")
                return
            log(f"→ {email}: 窗口已开, 登录 {TARGET_URL} ...")
            r = _chatgpt_login(
                ws, a, lambda m: log(f"  [{email}] {m}"), _upstream(),
                should_stop=_stopped)
            if r == "stopped":
                a["status"] = "stopped"
                OPEN_JOB["results"][a["id"]] = "已手动停止"
                log(f"⏹ {email}: 已停止")
                return
            if r in ("ok", "ok_new"):
                a["status"] = "opened"
                a["reg"] = "new" if r == "ok_new" else "yes"
                a["reg_at"] = _now()
                OPEN_JOB["results"][a["id"]] = "ok"
                log(f"✓ {email}: "
                    + ("新注册完成" if r == "ok_new"
                       else "登录完成 (已是注册号)"))
            elif r == "no_mail":
                a["status"] = "opened"
                OPEN_JOB["results"][a["id"]] = "邮箱已提交, 无接码链接"
                log(f"✓ {email}: 窗口已就绪 (缺接码链接, 手动收码)")
            elif r == "email_dead":
                a["status"] = "email_dead"
                a["email_dead"] = True
                OPEN_JOB["results"][a["id"]] = "邮箱不可用 (602)"
                log(f"✗ {email}: 邮箱账号已失效 — 跳过")
            else:
                a["status"] = "login_failed"
                OPEN_JOB["results"][a["id"]] = r
                log(f"✗ {email}: 登录中断 — {r}")
        except Exception as e:
            OPEN_JOB["results"][a["id"]] = str(e)[:120]
            log(f"✗ {email}: {str(e)[:120]}")
        finally:
            _persist(a)
    try:
        with ThreadPoolExecutor(max_workers=OPEN_WORKERS) as ex:
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
         "/settings": "settings.html", "/settings.html": "settings.html"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

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
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in PAGES:
            return self._file(PAGES[self.path])
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
                "cpa_url": s.get("cpa_url") or "",
                "cpa_key": s.get("cpa_key") or ""})
        if self.path == "/api/accounts":
            accs = _load_accounts()
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
                     "bound": sum(1 for a in accs if a.get("proxy_id")),
                     "opened": sum(1 for a in accs if a.get("win")),
                     "reg": sum(1 for a in accs
                                if a.get("reg") in ("new", "yes")),
                     "unbound": sum(1 for a in accs
                                    if not a.get("proxy_id"))}
            return self._json({"accounts": out, "stats": stats,
                               "target": TARGET_URL})
        if self.path == "/api/accounts/open/status":
            return self._json({"running": OPEN_JOB["running"],
                               "log": OPEN_JOB["log"][-80:],
                               "results": OPEN_JOB["results"]})
        if self.path == "/api/accounts/pat/status":
            return self._json({"running": PAT_JOB["running"],
                               "log": PAT_JOB["log"][-80:],
                               "results": PAT_JOB["results"]})
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
                for k, v in MAIL_WATCH.items()],
                "profiles": [
                    {"id": k, **v} for k, v in PROF_WATCH.items()]})
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
                    {"error": "没有可导出的凭证 (先跑🔗OAuth授权)"})
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
                      "cpa_url", "cpa_key"):
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
                      "mail_url"):
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
        if self.path == "/api/accounts/open":
            req = self._body()
            if OPEN_JOB["running"]:
                return self._json({"error": "已有开窗任务在跑"}, 409)
            ids = set(req.get("ids") or [])
            accs = [a for a in _load_accounts()
                    if not ids or a["id"] in ids]
            if not accs:
                return self._json({"error": "没有要开的账号"})
            if len(accs) > 50:
                return self._json({"error": "单次最多 50 个"}, 400)
            threading.Thread(
                target=_open_worker,
                args=(accs, bool(req.get("semiauto")),
                      bool(req.get("watch_code", True)),
                      bool(req.get("gen_profile", True)),
                      bool(req.get("auto_email", True)),
                      bool(req.get("auto_code", True)),
                      bool(req.get("auto_profile", True))),
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
            w = MAIL_WATCH.get(req.get("id"))
            if w:
                w["stop"] = True
            return self._json({"ok": True})
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
                                x.update(a)
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
                    "对不上账号 (state 匹配失败)"
                    if state else
                    "多个账号在等回调, 请贴带 state= 的完整链接"
                    if len(pend) > 1 else
                    "没有在等回调的账号 (先跑🔗OAuth授权)"})
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
        if self.path == "/api/settings/test-cpa":
            # 连通性: GET <cpa>/v8/management/credentials
            # (v8 不在退回 /v0/management/api-keys) ——
            # 顺带验证了管理 key 是否有效
            req = self._body()
            s = _settings()
            url = (req.get("url") or s.get("cpa_url")
                   or "").strip().rstrip("/")
            key = req.get("key") or s.get("cpa_key") or ""
            if not url:
                return self._json({"error": "先填 CPA 地址"})
            if "://" not in url:
                url = "http://" + url
            hdrs = {"Authorization": "Bearer " + key} if key else None
            up = _upstream() if url.startswith("https://") else None
            t0 = time.time()
            try:
                st, body = _https_status_get(
                    url + "/v8/management/credentials",
                    up, 12, headers=hdrs)
                ver = "v8"
                if st == 404:
                    st, body = _https_status_get(
                        url + "/v0/management/api-keys",
                        up, 12, headers=hdrs)
                    ver = "v0"
                ms = int((time.time() - t0) * 1000)
                if st in (401, 403):
                    return self._json(
                        {"error": f"管理 Key 无效或未授权 ({st})",
                         "ms": ms})
                if st != 200:
                    return self._json(
                        {"error": f"HTTP {st}: "
                                  f"{body[:160].decode(errors='ignore')}",
                         "ms": ms})
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
                return self._json({"ok": True, "ms": ms, "ver": ver,
                                   "creds": n})
            except Exception as e:
                return self._json({"error": str(e)[:200]})
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
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
