#!/usr/bin/env python3
"""GPT 上号器 (移植自 deintel cpa-monitor pusher): 绑定 settings 里配置的
CPA 号池, 自动把 accounts 里 `cpa=ready` 的预备凭证补进池, 维持
needed = 1 + floor(pool_rpm / capacity_rpm) 个可用号
(rpm 取远端 CPA /v0/management/logs 增量解析, 窗口 rpm_win_min 分钟)。

可用判据 (任一不过即不计入可用):
  quota    - CPA 捕获的最低额度桶低于 pct (信号过期时钉选刷新)
  deg      - CPA 侧失效: unavailable / 账号级冷却 / probe_model 冷却 /
             status 非 active
  errrate  - 账号近 N 分钟请求错误率 > pct (最小请求数门限)
  timer    - 入池超过 max 分钟强制轮换

每个 tick 缺口 (needed - usable) 触发一次推送, min_gap_s 防抖。
只增不减: rpm 掉了多出的号留在池里。推送 = 复用 server._cpa_push_cred。

状态存 gpusher.json; 依赖全部由 server.py init() 注入, 不反向 import。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from urllib.parse import quote

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(BASE, "gpusher.json")

RETRY_S = 60          # transport 级推送失败后的退避
EMPTY_LOG_S = 300     # “无预备号” 事件节流
TICK_LOG_LIMIT = 5000
LOG_KEEP_S = 6 * 3600
POOL_CACHE_S = 30
EVENT_KEEP = 200

_lock = threading.RLock()
_state = None          # dict, 见 _load()
_reqs = []             # 内存请求流水 [(ts,status,account)] —— 重启重建即可
_pool_cache = {"key": None, "ts": 0.0, "rows": None}
_last_empty_log = [0.0]

# ---- 注入依赖 (server.py 启动时绑) ----
_cpa_call = None       # (method, path, body, timeout) -> (st, json, err)
_push_cred = None      # (name, cred) -> err|None
_get_settings = None   # () -> dict (cpa_url/cpa_key 等)
_save_settings = None  # (dict) -> None
_load_accs = None      # () -> [account]
_save_accs = None      # ([account]) -> None
_cred_name = None      # (cred) -> filename
_now = None            # () -> "YYYY-mm-ddTHH:MM:SS"


def init(cpa_call, push_cred, get_settings, save_settings,
         load_accs, save_accs, cred_name, now):
    global _cpa_call, _push_cred, _get_settings, _save_settings
    global _load_accs, _save_accs, _cred_name, _now
    _cpa_call, _push_cred = cpa_call, push_cred
    _get_settings, _save_settings = get_settings, save_settings
    _load_accs, _save_accs = load_accs, save_accs
    _cred_name, _now = cred_name, now
    _load()


# ------------------------------------------------------------- state --

def _default_conf():
    return {
        "mode": "local",                # local | remote
        "remote_url": "",               # 远程上号器 ext API (如 http://10.13.13.11:8397)
        "remote_key": "",               # ext-... Bearer key
        "remote_pool": "",              # 池标识, 空=cpa_url 端口
        "capacity_rpm": 60, "rpm_win_min": 5, "min_gap_s": 60,
        "quota_on": False, "quota_pct": 5, "quota_probe_s": 300,
        "deg_on": False,
        "err_on": False, "err_win_min": 10, "err_pct": 50, "err_min_n": 100,
        "timer_on": False, "timer_min": 180,
        "refresh_on": False, "refresh_min": 100,
        "probe_api_key": "", "probe_model": "gpt-6-astra",
    }


def _load():
    global _state
    try:
        _state = json.load(open(STATE_FILE))
    except Exception:
        _state = {}
    _state.setdefault("conf", {})
    _state.setdefault("events", [])
    _state.setdefault("running", False)
    _state.setdefault("logs_cursor", 0.0)
    _state.setdefault("retry_at", 0.0)
    _state.setdefault("refresh_ts", 0.0)
    _state.setdefault("push_err", {})
    _state.setdefault("probe_ts", {})
    _state.setdefault("probe_err", {})
    _state.setdefault("remote_sent", {})
    # remote_sent 旧格式 {email: ts} → 新 {email|ws: {file,ts}}
    # 去重键 = 账号+空间 (同账号不同空间 = 不同凭证, 都要投;
    # 同账号同空间 = 同一凭证, 不重复投)
    sent = _state["remote_sent"]
    dirty = False
    accs = None
    for k, v in list(sent.items()):
        if "|" in k and isinstance(v, dict):
            continue
        if accs is None:
            try:
                accs = _load_accs() or []
            except Exception:
                accs = []
        em = k.split("|")[0].lower()
        a = next((x for x in accs
                  if (x.get("email") or "").lower() == em), None)
        nk = _sent_key(a) if a else em + "|"
        sent[nk] = {"file": (a or {}).get("cred_file"),
                    "ts": v.get("ts") if isinstance(v, dict) else v}
        if nk != k:
            sent.pop(k, None)
        dirty = True
    if dirty:
        _save()
    return _state


def _save():
    tmp = STATE_FILE + ".tmp"
    json.dump(_state, open(tmp, "w"), ensure_ascii=False, indent=1)
    os.replace(tmp, STATE_FILE)


def get_conf():
    c = dict(_default_conf())
    c.update(_state.get("conf") or {})
    s = _get_settings() or {}
    c["addr"] = (s.get("cpa_url") or "").strip()
    c["has_key"] = bool((s.get("cpa_key") or "").strip())
    return c


def save_conf(upd):
    upd = dict(upd)
    # 前端字段别名 → 内部键
    if "cpa_url" in upd:
        upd["addr"] = upd.pop("cpa_url")
    if "cpa_key" in upd:
        upd["key"] = upd.pop("cpa_key")
    if "api_key" in upd:
        upd["probe_api_key"] = upd.pop("api_key")
    # CPA 地址/密码回写 settings —— 与设置页同源
    s = _get_settings() or {}
    changed_s = False
    if "addr" in upd:
        s["cpa_url"] = upd.pop("addr").strip()
        changed_s = True
    if "key" in upd and upd["key"]:
        s["cpa_key"] = upd.pop("key").strip()
        changed_s = True
    else:
        upd.pop("key", None)
    if "probe_api_key" in upd and not upd["probe_api_key"]:
        upd.pop("probe_api_key")
    if "remote_key" in upd and not upd["remote_key"]:
        upd.pop("remote_key")
    if upd.get("mode") not in ("local", "remote"):
        upd.pop("mode", None)
    allowed = set(_default_conf())
    _state["conf"].update({k: v for k, v in upd.items() if k in allowed})
    with _lock:
        _save()
    if changed_s:
        _save_settings(s)
    return {"ok": True}


def log_ev(email, event, detail=""):
    with _lock:
        _state["events"].insert(0, {"ts": time.time(), "event": event,
                                    "email": email or "",
                                    "detail": (detail or "")[:300]})
        del _state["events"][EVENT_KEEP:]
        _save()


# -------------------------------------------------------------- mgmt --

def mgmt(path, payload=None, raw=None, method=None, timeout=20):
    """走 server._cpa_call, 统一返回 (json, err, kind)。kind: ''|http|transport|cfg
    路径照 server 惯例: /v8/management 优先, 404 降级 /v0/management。"""
    conf = get_conf()
    if not conf["addr"]:
        return None, "CPA 地址未配置 (设置页)", "cfg"
    if not conf["has_key"]:
        return None, "管理密钥未配置 (设置页 cpa_key)", "cfg"
    body = raw if raw is not None else payload
    m = method or ("POST" if body is not None else "GET")
    if path == "/auth-files":
        # v8 列表在 credentials; v0 在 auth-files
        cands = ["/v8/management/credentials",
                 "/v0/management/auth-files"]
    else:
        cands = ["/v8/management" + path,
                 "/v0/management" + path]
    last = (0, None, None)
    for p in cands:
        st, j, err = _cpa_call(m, p, body, timeout)
        if st == 404:
            last = (st, j, err)
            continue
        if err:
            return None, err, ("http" if st else "transport")
        return j, None, ""
    st, j, err = last
    return None, err or "HTTP 404", "http"


def _parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


# ------------------------------------------------- remote ext API (远程上号器) --

def _remote_conf():
    """(url, pool, key)。url 空时按 cpa_url 主机 + 8397 推导; pool 空取 cpa 端口。"""
    conf = get_conf()
    url = (conf.get("remote_url") or "").strip()
    pool = (conf.get("remote_pool") or "").strip()
    if not pool:
        m = re.search(r":(\d{2,5})/?$", conf["addr"])
        pool = m.group(1) if m else ""
    if not url:
        h = re.match(r"(?:https?://)?([^/:]+)", conf["addr"])
        url = "http://%s:8397" % h.group(1) if h else ""
    return url, pool, (conf.get("remote_key") or "").strip()


def remote_call(method, path, body=None, timeout=20):
    """远程上号器 ext API → (status, json, err)。path 形如 /queue?pool=.."""
    url, pool, key = _remote_conf()
    if not url:
        return 0, None, "远程上号器地址未配置"
    if not key:
        return 0, None, "远程 API Key 未配置 (ext-...)"
    if "://" not in url:
        url = "http://" + url
    if pool and "pool=" not in path and "pool" not in (body or {}):
        sep = "&" if "?" in path else "?"
        path = path + sep + "pool=" + quote(str(pool))
    data = json.dumps(body, ensure_ascii=False).encode() \
        if body is not None else None
    req = urllib.request.Request(
        url.rstrip("/") + "/api/ext" + path, data=data,
        method=method.upper(),
        headers={"Authorization": "Bearer " + key,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            b = r.read()
    except urllib.error.HTTPError as e:
        return e.code, None, "HTTP %d: %s" % (
            e.code, e.read()[:160].decode(errors="ignore"))
    except Exception as e:
        return 0, None, "%s: %s" % (type(e).__name__, str(e)[:140])
    try:
        return 200, json.loads(b) if b else {}, None
    except Exception:
        return 200, {}, None


def _remote_status():
    return remote_call("GET", "/status")


def _remote_queue(status_="pending", limit=200):
    return remote_call(
        "GET", "/queue?status=%s&limit=%d" % (status_, limit))


def _remote_control(action):
    _, pool, _ = _remote_conf()
    return remote_call("POST", "/control", {"pool": pool, "action": action})


def _remote_archive_list(status_="pending", limit=100):
    """GET /archive —— 查看归档队列 (不租用)。"""
    return remote_call(
        "GET", "/archive?status=%s&limit=%d" % (status_, limit))


def _remote_archive_claim(limit=10, lease_s=900):
    """POST /archive/claim —— 租用取号 (带凭证原文)。"""
    _, pool, _ = _remote_conf()
    return remote_call("POST", "/archive/claim",
                       {"pool": pool, "limit": limit,
                        "lease_s": lease_s}, timeout=30)


def _remote_archive_ack(ids):
    """POST /archive/ack —— 处理成功确认。"""
    return remote_call("POST", "/archive/ack", {"ids": ids})


def _remote_archive_fail(iid, err):
    """POST /archive/fail —— 处理失败重排队尾。"""
    return remote_call("POST", "/archive/fail",
                       {"id": iid, "error": err})


def _submit_files(files):
    """files=[{name,content}] → (added_n, err)。批量 /queue 提交。"""
    _, pool, _ = _remote_conf()
    st, j, err = remote_call("POST", "/queue",
                             {"pool": pool, "files": files}, timeout=30)
    if err:
        return 0, err
    return len((j or {}).get("items") or []), None


def pool_accounts(force=False):
    """池内 auth files。 [{name,email,disabled,status,modtime,quota,...}]
    不可达返回 None。"""
    conf = get_conf()
    now = time.time()
    if not force and _pool_cache["key"] == conf["addr"] and \
            now - _pool_cache["ts"] < POOL_CACHE_S:
        return _pool_cache["rows"]
    rows = None
    res, err, _ = mgmt("/auth-files")
    _state["pool_err"] = (err or "")[:200]
    if res is None and not conf["addr"]:
        return None
    if res is not None:
        if isinstance(res, list):
            files = res
        else:
            files = (res.get("files") or res.get("credentials")
                     or res.get("items") or [])
        rows = [{
            "name": f.get("name") or f.get("filename") or "",
            "email": f.get("email") or canon_account(f.get("name")),
            "disabled": bool(f.get("disabled")),
            "status": f.get("status") or "",
            "status_message": f.get("status_message") or "",
            "unavailable": bool(f.get("unavailable")),
            "cooldowns": f.get("cooldowns") or [],
            "modtime": _parse_ts(f.get("modtime") or f.get("updated_at")),
            "quota": f.get("quota"),
            "model_quotas": f.get("model_quotas"),
        } for f in files]
        for a in rows:
            a["quota_ts"] = quota_observed_ts(a)
            a["quota_pct"] = quota_remaining_pct(a)
    _pool_cache.update(key=conf["addr"], ts=now, rows=rows)
    return rows


EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def canon_account(name):
    name = (name or "").rsplit("/", 1)[-1]
    if name.endswith(".json"):
        name = name[:-5]
    m = EMAIL_RE.search(name)
    return m.group(0) if m else name


def tag_for(email_or_name):
    local = email_or_name.split("@")[0]
    slug = re.sub(r"[^a-z0-9]", "", local.lower())[:8]
    if len(slug) < 3:
        slug = (slug + hashlib.sha1(
            email_or_name.encode()).hexdigest())[:8]
    return "acct-" + slug


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _sigsets(row):
    out = []
    q = row.get("quota") or {}
    if isinstance(q, dict) and q.get("signals"):
        out.append((q.get("observed_at"), q["signals"]))
    mq = row.get("model_quotas") or {}
    if isinstance(mq, dict):
        for m in mq.values():
            if isinstance(m, dict) and m.get("signals"):
                out.append((m.get("observed_at"), m["signals"]))
    return out


def quota_observed_ts(row):
    ts = [t for t in (_parse_ts(o) for o, _ in _sigsets(row)) if t]
    return max(ts) if ts else None


def quota_remaining_pct(row, now=None):
    """codex primary/secondary 窗口剩余 % 最小值; 已过 reset 的窗口算满。
    无信号返回 None。"""
    now = now or time.time()
    rems = []
    for _, s in _sigsets(row):
        for uk, rk in (("X-Codex-Primary-Used-Percent",
                        "X-Codex-Primary-Reset-At"),
                       ("X-Codex-Secondary-Used-Percent",
                        "X-Codex-Secondary-Reset-At")):
            u = _num(s.get(uk))
            if u is None:
                continue
            rt = _num(s.get(rk))
            if rt and rt < now:
                u = 0.0
            rems.append(100.0 - u)
    return min(rems) if rems else None


# ------------------------------------------------------ remote log sync --

LINE_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\] \[(?P<tag>[0-9a-f-]+)\] \[(?P<lvl>\w+)\s*\] "
    r"\[(?P<src>[^\]]+)\] (?P<msg>.*)$")
GIN_RE = re.compile(
    r"(?P<status>\d{3}) \|\s+(?P<lat>[\d.]+)(?P<unit>ms|s) \| \s*(?P<ip>\S+) "
    r"\| (?P<method>\w+)\s+\"(?P<path>[^\"]+)\"")
AFFINITY_RE = re.compile(r"auth=(?P<auth>\S+\.json)\b.*model=(?P<model>\S+)")
UPFAIL_RE = re.compile(
    r"(?P<status>\d{3}) \|\s+(?P<lat>[\d.]+)(?P<unit>ms|s) \| "
    r"upstream execution failed: provider=(?P<provider>\S+) "
    r"model=(?P<model>\S+) auth=.*?auth_file=(?P<auth>\S+) err=(?P<err>.*)")
TRACKED_PATHS = ("/v1/responses", "/v1/chat/completions", "/v1/messages",
                 "/backend-api/codex/responses", "/v1/completions")


def _line_ts(raw):
    try:
        return time.mktime(time.strptime(raw.strip(), "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return None


def sync_logs():
    """GET /v0/management/logs?after=<cursor> 增量拉日志, 解析 client 级请求
    入内存 _reqs [(ts,status,account)]。返回 (n_new, err)。"""
    cursor = _state["logs_cursor"]
    path = (f"/logs?after={int(cursor)}&limit={TICK_LOG_LIMIT}" if cursor
            else f"/logs?limit={TICK_LOG_LIMIT}")
    res, err, _ = mgmt(path, timeout=30)
    if res is None:
        return 0, err
    lines = res.get("lines") or []
    latest = res.get("latest-timestamp") or 0
    pending, rows, max_raw = {}, [], 0.0
    for line in lines:
        m = LINE_RE.match(line)
        if not m:
            continue
        tag, src, msg = m.group("tag"), m.group("src"), m.group("msg")
        ts = _line_ts(m.group("ts"))
        if ts and ts > max_raw:
            max_raw = ts
        g = GIN_RE.search(msg)
        if g and "gin_logger" in src:
            p = g.group("path").split("?")[0]
            if p in TRACKED_PATHS and ts:
                bind = pending.pop(tag, None) or {}
                rows.append((ts, int(g.group("status")),
                             bind.get("account", "")))
            continue
        u = UPFAIL_RE.search(msg)
        if u and ts:
            rows.append((ts, int(u.group("status")),
                         canon_account(u.group("auth"))))
            continue
        a = AFFINITY_RE.search(msg)
        if a and "selector" in src:
            pending[tag] = {"account": canon_account(a.group("auth"))}
    # 日志行时间是 CPA 本机时区, latest-timestamp 是真实 unix 时间:
    # 用最新行锚定差值平移, 任意时区差都正确
    off = (latest - max_raw) if latest and max_raw else 0.0
    if rows:
        cut = time.time() - LOG_KEEP_S
        _reqs[:] = [r for r in _reqs if r[0] > cut]
        _reqs.extend((ts + off, st, ac) for ts, st, ac in rows)
    if latest and latest > cursor:
        _state["logs_cursor"] = latest
        _save()
    return len(rows), None


def _win_end():
    return _reqs[-1][0] if _reqs else time.time()


def pool_rpm(conf):
    win = max(1, conf["rpm_win_min"])
    end = _win_end()
    n = sum(1 for r in _reqs if r[0] > end - win * 60)
    return n / win


def acct_errrate(conf, email):
    if not email:
        return None
    win = max(1, conf["err_win_min"])
    end = _win_end()
    n = bad = 0
    for ts, st, ac in _reqs:
        if ac == email and ts > end - win * 60:
            n += 1
            bad += st != 200
    if n >= conf["err_min_n"] and bad * 100 > conf["err_pct"] * n:
        return f"错误率{bad * 100 // n}%"
    return None


# ---------------------------------------------------------- eval / push --

def _local_ts(s):
    """accounts 的 cpa_at ("%Y-%m-%dT%H:%M:%S" 本地) → epoch"""
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return None


def acct_state(conf, a):
    """CPA 条目 → 健康态: 'cooldown'|'dead'|'disabled'|'active'。
    判据口径: 账号级/目标模型冷却、unavailable、status 非 active。"""
    if a["disabled"]:
        return "disabled"
    if a.get("unavailable"):
        return "dead"
    now = time.time()
    model = conf.get("probe_model") or ""
    for cd in a.get("cooldowns") or []:
        if (cd.get("remaining_seconds") or 0) <= 0:
            continue
        if cd.get("scope") == "account" or \
                (model and model in (cd.get("model_key") or "")):
            return "cooldown"
    st = (a.get("status") or "").lower()
    if st and st not in ("active", "ok", "healthy"):
        return "dead"
    return "active"


def eval_pool(conf, accts):
    """容量模型: needed = 1 + floor(rpm / capacity); 可用 = 启用且过全部判据。"""
    now = time.time()
    rpm = pool_rpm(conf)
    needed = 1 + int(rpm / max(1, conf["capacity_rpm"]))
    accs_by_name = {}
    for a in (_load_accs() or []):
        if a.get("cred_file"):
            accs_by_name[a["cred_file"]] = a
    verdicts, usable = {}, []
    for a in accts:
        reasons = []
        if a["disabled"]:
            reasons.append("停用")
        else:
            st = acct_state(conf, a)
            a["acct_state"] = st
            if conf["deg_on"] and st != "active":
                reasons.append("冷却" if st == "cooldown" else "失效")
            if conf["quota_on"]:
                pct = a.get("quota_pct")
                if pct is not None and pct < conf["quota_pct"]:
                    reasons.append(f"额度{pct:.0f}%")
            if conf["err_on"]:
                e = acct_errrate(conf, a.get("email") or "")
                if e:
                    reasons.append(e)
            if conf["timer_on"]:
                ours = accs_by_name.get(a["name"]) or {}
                entry = (_local_ts(ours.get("cpa_at") or "")
                         or a.get("modtime") or now)
                age = (now - entry) / 60
                if age > conf["timer_min"]:
                    reasons.append(f"在池{age:.0f}min")
        ok = not reasons
        verdicts[a["name"]] = {"ok": ok, "reasons": reasons}
        if ok:
            usable.append(a)
    return {"rpm": rpm, "needed": needed, "usable": usable,
            "verdicts": verdicts, "deficit": max(0, needed - len(usable)),
            "reason": f"补位 {len(usable)}/{needed} · rpm {rpm:.0f}"}


def _ensure_pin_prefix(cur):
    """确保 auth file 带 prefix → `{prefix}/{model}` 钉选路由。"""
    tag = tag_for(cur.get("email") or cur["filename"])
    res, err, _ = mgmt("/auth-files/fields",
                       {"name": cur["filename"], "prefix": tag},
                       method="PATCH")
    return tag if res is not None else None


def quota_probe(conf, cur):
    """钉选一条最小请求让 CPA 捕获新额度头。返回 err|None。"""
    prefix = _ensure_pin_prefix(cur)
    if not prefix:
        return "无 prefix, 无法钉选该账号"
    addr = conf["addr"]
    api_key = conf["probe_api_key"]
    if not addr or not api_key:
        return "addr/probe_api_key 未配置"
    if "://" not in addr:
        addr = "http://" + addr
    body = {"model": f'{prefix}/{conf["probe_model"]}', "store": False,
            "stream": False, "reasoning": {"effort": "low"},
            "max_output_tokens": 64,
            "input": [{"type": "message", "role": "user",
                       "content": [{"type": "input_text", "text": "0"}]}]}
    req = urllib.request.Request(
        addr.rstrip("/") + "/v1/responses",
        data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + api_key,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        return None
    except urllib.error.HTTPError:
        return None     # 4xx/5xx 也带新额度头
    except Exception as e:
        return f"{type(e).__name__}: {e}"


def _quota_probe_bg(conf, cur):
    _state["probe_err"][cur["filename"]] = quota_probe(conf, cur)


def _refresh_quota_signals(conf, accts, verdicts):
    if not conf["quota_on"] or not conf["probe_api_key"]:
        return
    now = time.time()
    for a in accts:
        if a["disabled"]:
            continue
        v = verdicts.get(a["name"]) or {}
        if v.get("reasons") and any(
                r in ("冷却", "失效") for r in v["reasons"]):
            continue
        obs = a.get("quota_ts")
        if obs is not None and now - obs <= conf["quota_probe_s"]:
            continue
        if now - _state["probe_ts"].get(a["name"], 0) < conf["quota_probe_s"]:
            continue
        _state["probe_ts"][a["name"]] = now
        threading.Thread(
            target=_quota_probe_bg,
            args=(conf, {"filename": a["name"],
                         "email": a.get("email") or ""}),
            daemon=True).start()
        break


def _alive(a):
    """可上号的账号: 未归档 + 邮箱没死。"""
    return not a.get("archived") and not a.get("email_dead")


def _standby(accs):
    """预备账号 = 活的(未归档/邮箱没死) + 有凭证且未入池 (cpa=ready)。"""
    return sorted(
        (a for a in accs
         if _alive(a) and a.get("cred") and a.get("cpa") == "ready"),
        key=lambda a: a.get("cred_at") or "")


def _queue_cred(cred):
    """进远程队列的凭证 content —— 注入 max_concurrency
    (与 server._cpa_cred_out 同口径, 默认40)。"""
    d = dict(cred)
    try:
        mc = int((_get_settings() or {}).get("cpa_max_concurrency")
                 or 40)
    except (TypeError, ValueError):
        mc = 40
    d["max_concurrency"] = max(1, mc)
    return d


def _sent_key(a, ws=None):
    """队列去重键 = 账号 + 凭证所属空间。
    同账号不同空间 = 不同凭证都要投; 同账号同空间 = 重复。"""
    if ws is None:
        ws = (a.get("cred_ws") or a.get("space_ws") or "")
    return "%s|%s" % ((a.get("email") or "").lower(), ws)


def _acc_creds(a):
    """账号的全部待用凭证 → [(ws, cred, file, at)]。
    新结构 a['creds']={ws:{cred,file,at}} (一账号多空间,
    后者不覆盖前者); 兼容旧单槽 a['cred']。"""
    multi = a.get("creds") or {}
    if multi:
        return [(ws, e.get("cred"), e.get("file"), e.get("at"))
                for ws, e in multi.items() if e.get("cred")]
    if a.get("cred"):
        return [(a.get("cred_ws") or a.get("space_ws") or "",
                 a["cred"], a.get("cred_file"), a.get("cred_at"))]
    return []


def _pending_files(accs):
    """本地 cpa=ready 账号的全部空间凭证 → [{name,content,acc,ws,at}]。
    (是否已在远程队列由调用方按 pending 名单判)"""
    out = []
    for a in accs:
        if not (_alive(a) and a.get("cpa") == "ready"):
            continue
        for ws, cred, fn, at in _acc_creds(a):
            out.append({"acc": a, "ws": ws, "at": at,
                        "name": fn or _cred_name(cred, ws),
                        "content": _queue_cred(cred)})
    return out


def _remote_pending_map(limit=500):
    """远程 pending 队列 {filename: item_id}; 出错 (None, err)。"""
    st, j, err = _remote_queue("pending", limit)
    if err:
        return None, err
    return {(it.get("filename") or it.get("name") or ""):
            it.get("id")
            for it in (j or {}).get("items") or []}, None


def _cred_prefix(a, ws=None):
    """同账号同空间的文件名前缀 codex-<email>-<ws8>-
    —— 匹配远程 pending 里我们没记录的同键项 (state丢/
    他人推的/plan变名)。"""
    a = a or {}
    em = (a.get("email") or "unknown").strip()
    if ws is None:
        ws = (a.get("cred_ws") or a.get("space_ws") or "")
    w = (ws or "").strip()[:8] or "main"
    return "codex-%s-%s-" % (em, w)


def _dedup_feed(files, pending):
    """按 账号+空间 去重 → (todo, stale_ids):
    - 同名文件仍在远程 pending 且凭证没重生成 → 已在队, 跳过
    - 同键但文件名不同 (旧随机名 / plan 变 / 未记录的) 且
      旧文件仍在队 → 记 stale, 推新前删掉 —— 同账号同空间
      远程只留一个
    - 不同空间 = 不同键 → 必投"""
    sent = _state["remote_sent"]
    todo, stale = [], []
    for f in files:
        rec = sent.get(_sent_key(f["acc"], f.get("ws")))
        if rec:
            old = rec.get("file")
            if old == f["name"] and old in pending:
                ts = _local_ts(f.get("at")
                               or f["acc"].get("cred_at") or "")
                if not ts or ts <= (rec.get("ts") or 0):
                    continue                # 同一凭证已在队
            elif old and old != f["name"] and pending.get(old):
                stale.append(pending[old])
        # 前缀扫: 同账号同空间但名字不同的在队项 → 顶掉
        pre = _cred_prefix(f["acc"], f.get("ws"))
        for pn, pid in pending.items():
            if (pn != f["name"] and pn.startswith(pre)
                    and pid and pid not in stale):
                stale.append(pid)
        todo.append(f)
    return todo, stale


def _del_stale(stale_ids):
    """推新凭证前把同键的旧 pending 项删掉 (best-effort)。"""
    for i in stale_ids:
        remote_call("DELETE", "/queue/%s" % i, timeout=15)


def _feed_remote(conf, reason="tick"):
    """把本地 ready 凭证批量投喂远程队列 → (added, err)。"""
    url, pool, _ = _remote_conf()
    if not url or not pool:
        return 0, "远程上号器未配置完整 (url/pool)"
    sent = _state["remote_sent"]
    accs = _load_accs() or []
    files = _pending_files(accs)[:500]
    if not files:
        return 0, None
    pending, perr = _remote_pending_map()
    if perr:
        _state["remote_err"] = perr[:200]
        return 0, perr
    todo, stale = _dedup_feed(files, pending)
    # 已入池的文件不再投 (远程推送后 reconcile 没跑到的间隙,
    # 同名虽只是 upsert 但浪费一轮)
    pool_names = {r["name"] for r in (pool_accounts() or [])}
    if pool_names:
        consumed = [f for f in todo if f["name"] in pool_names]
        if consumed:
            for f in consumed:
                a = f["acc"]
                if a.get("cpa") != "yes":
                    a["cpa"] = "yes"; a["cpa_at"] = _now()
                if a.get("creds"):
                    a["creds"].pop(f.get("ws") or "", None)
            _save_accs(accs)
            todo = [f for f in todo
                    if f["name"] not in pool_names]
    if not todo:
        return 0, None
    if stale:
        _del_stale(stale)
    st, j, err = remote_call(
        "POST", "/queue",
        {"pool": pool,
         "files": [{"name": f["name"], "content": f["content"]}
                   for f in todo]}, timeout=30)
    if err:
        _state["remote_err"] = err[:200]
        return 0, err
    _state.pop("remote_err", None)
    skipped = {s.get("name") for s in (j or {}).get("skipped") or []}
    now = time.time()
    n = 0
    for f in todo:
        if f["name"] in skipped:
            continue
        sent[_sent_key(f["acc"], f.get("ws"))] = {
            "file": f["name"], "ts": now}
        f["acc"]["cred_file"] = f["name"]
        n += 1
    if n:
        _save_accs(accs)
        log_ev("", "queued_remote",
               f"投喂 {n} 个 → {url} pool={pool} ({reason})")
    _save()
    return n, None


def push_next(reason="manual"):
    """本地模式: 直推 CPA。远程模式: 投喂一个 + 让远程立即推。"""
    conf = get_conf()
    accs = _load_accs() or []
    sb = _standby(accs)
    if conf.get("mode") == "remote":
        if sb:
            f = _pending_files(sb)[:1]
            if f:
                _, pool, _ = _remote_conf()
                pending, _ = _remote_pending_map()
                if pending is not None:
                    todo, stale = _dedup_feed(f, pending)
                else:
                    todo, stale = f, []
                if todo:
                    _del_stale(stale)
                    st, j, err = remote_call(
                        "POST", "/queue",
                        {"pool": pool, "name": f[0]["name"],
                         "content": f[0]["content"]}, timeout=30)
                    if err:
                        return {"ok": False, "err": "投喂失败: " + err}
                    _state["remote_sent"][
                        _sent_key(sb[0], f[0].get("ws"))] = {
                        "file": f[0]["name"], "ts": time.time()}
                    sb[0]["cred_file"] = f[0]["name"]
                    _save_accs(accs)
                    log_ev(sb[0]["email"], "queued_remote",
                           f"{f[0]['name']} → 远程队列")
        st, j, err = _remote_control("push_next")
        if err:
            return {"ok": False, "err": "远程 push_next: " + err}
        return {"ok": True, "msg": (j or {}).get("msg") or "已触发远程推送"}
    if not sb:
        if time.time() - _last_empty_log[0] > EMPTY_LOG_S:
            _last_empty_log[0] = time.time()
            log_ev("", "queue_empty", f"trigger: {reason}")
        return {"ok": False, "err": "预备账号为空 (无 cpa=ready 的凭证)"}
    a = sb[0]
    name = a.get("cred_file") or _cred_name(a["cred"])
    err = _push_cred(name, a["cred"])
    now = time.time()
    if not err:
        a["cpa"] = "yes"
        a["cpa_at"] = _now()
        a["cred_file"] = name
        _state["push_err"].pop(a["email"], None)
        _save_accs(accs)
        _save()
        log_ev(a["email"], "pushed", f"{name} → {conf['addr']} ({reason})")
        return {"ok": True, "pushed": name, "email": a["email"]}
    _state["push_err"][a["email"]] = err[:200]
    _save()
    _state["retry_at"] = now + RETRY_S
    log_ev(a["email"], "push_failed", f"{name}: {err}")
    return {"ok": False, "err": err, "email": a["email"]}


def _maybe_refresh(conf):
    """每 refresh_min 分钟让 CPA 全量刷新凭证 (RT→AT)。"""
    if not conf["refresh_on"] or not conf["addr"]:
        return
    now = time.time()
    if now - _state["refresh_ts"] < conf["refresh_min"] * 60:
        return
    _state["refresh_ts"] = now
    _save()
    res, err, _ = mgmt("/auth-files/refresh?all=true", {})
    if err:
        log_ev("", "refresh_failed", err[:200])
        return
    rs = (res or {}).get("results") or []
    ok = sum(1 for r in rs if r.get("success"))
    bad = len(rs) - ok
    log_ev("", "refreshed",
           f"全量凭证刷新 {ok} 成功" + (f"，{bad} 失败" if bad else ""))


def tick():
    """20s 一跳: 同步日志 → (running 时) 评估缺口 → 推一个。
    远程模式: 只负责把本地 ready 凭证投喂进远程队列, 推送由远程调度器做。"""
    conf = get_conf()
    _maybe_refresh(conf)
    if conf.get("mode") == "remote":
        if _state["running"]:
            _feed_remote(conf, "tick")
        return
    if not conf["addr"] or not conf["has_key"]:
        return
    n, lerr = sync_logs()
    _state["logs_err"] = (lerr or "")[:200]
    if not _state["running"]:
        return
    if time.time() < _state["retry_at"]:
        return
    accts = pool_accounts()
    if accts is None:
        return
    ev = eval_pool(conf, accts)
    _refresh_quota_signals(conf, accts, ev["verdicts"])
    if ev["deficit"] <= 0:
        return
    if time.time() - _state.get("last_push_ts", 0) < conf["min_gap_s"]:
        return
    r = push_next(ev["reason"])
    if r.get("ok"):
        _state["last_push_ts"] = time.time()
        _save()


def loop(period=20):
    while True:
        try:
            tick()
        except Exception as e:
            try:
                log_ev("", "tick_error", f"{type(e).__name__}: {e}"[:200])
            except Exception:
                pass
        time.sleep(period)


def control(action, b=None):
    b = b or {}
    remote = get_conf().get("mode") == "remote"
    if remote and action in ("start", "stop", "push_next",
                             "retry_failed", "clear_done", "clear_pending"):
        st, j, err = _remote_control(action)
        if err:
            _state["remote_err"] = err[:200]
            _save()
            return {"ok": False, "err": "远程上号器: " + err}
        _state.pop("remote_err", None)
        if action in ("start", "stop"):
            _state["running"] = action == "start"
            _save()
            log_ev("", "started" if action == "start" else "stopped",
                   "远程模式")
            if action == "start":
                _feed_remote(get_conf(), "start")   # 立即投喂一轮
        return {"ok": True,
                "msg": (j or {}).get("msg") or f"远程 {action} 已执行",
                "remote": j}
    if action == "enqueue_all":
        if not remote:
            return {"ok": False, "err": "仅远程模式可投喂"}
        n, err = _feed_remote(get_conf(), "manual")
        if err:
            return {"ok": False, "err": err}
        return {"ok": True, "msg": f"已投喂 {n} 个预备凭证进远程队列"}
    if action == "enqueue_sel":
        # 账号页「推队列」: 选中账号的凭证批量提交远程队列 (不直接进池)
        if not remote:
            return {"ok": False,
                    "err": "上号器队列仅远程模式可用 (到上号器页切远程)"}
        ids = set(b.get("ids") or [])
        accs = _load_accs() or []
        _, pool, _ = _remote_conf()
        sent = _state["remote_sent"]
        files, failed = [], {}
        for a in accs:
            if a.get("id") not in ids:
                continue
            if a.get("archived"):
                failed[a["email"]] = "已归档 (死号)"
                continue
            if a.get("email_dead"):
                failed[a["email"]] = "邮箱已死"
                continue
            ents = _acc_creds(a)
            if not ents:
                failed[a["email"]] = "没有凭证 (先跑OAuth)"
                continue
            for ws, cred, fn, at in ents:
                files.append({"acc": a, "ws": ws, "at": at,
                              "name": fn or _cred_name(cred, ws),
                              "content": _queue_cred(cred)})
        if not files:
            return {"ok": 0, "err": "选中账号没有可提交的凭证",
                    "failed": failed or None}
        pending, perr = _remote_pending_map()
        if perr:
            return {"ok": 0, "err": "远程队列不可达: " + perr,
                    "failed": failed or None}
        todo, stale = _dedup_feed(files, pending)
        todo_ids = {id(f) for f in todo}
        for f in files:
            if id(f) not in todo_ids:
                failed[f["acc"]["email"]] = "已在队列 (同空间, 不重复投)"
        if stale:
            _del_stale(stale)
        ok = 0
        for i in range(0, len(todo), 500):
            chunk = todo[i:i + 500]
            st, j, err = remote_call(
                "POST", "/queue",
                {"pool": pool,
                 "files": [{"name": f["name"], "content": f["content"]}
                           for f in chunk]}, timeout=30)
            if err:
                for f in chunk:
                    failed[f["acc"]["email"]] = err
                continue
            skipped = {s.get("name"): s.get("err")
                       for s in (j or {}).get("skipped") or []}
            now = time.time()
            for f in chunk:
                if f["name"] in skipped:
                    failed[f["acc"]["email"]] = skipped[f["name"]]
                    continue
                sent[_sent_key(f["acc"], f.get("ws"))] = {
                    "file": f["name"], "ts": now}
                f["acc"]["cred_file"] = f["name"]
                ok += 1
        if ok:
            _save_accs(accs)
            _save()
            log_ev("", "queued_remote",
                   f"手动投喂 {ok} 个 → {pool} (账号页选中)")
        return {"ok": ok, "failed": failed or None}
    if action == "del_queue":
        if not remote:
            return {"ok": False, "err": "仅远程模式可删队列项"}
        st, j, err = remote_call("DELETE", "/queue/%s" % b.get("id", ""))
        if err:
            return {"ok": False, "err": err}
        return {"ok": True, "msg": "已删除"}
    if action == "start":
        _state["running"] = True
        _save()
        log_ev("", "started", "")
        conf = get_conf()
        accts = pool_accounts(force=True)
        if accts is None:
            return {"ok": True, "msg": "已启动 (号池暂不可达, 自动重试)"}
        ev = eval_pool(conf, accts)
        if ev["deficit"] > 0:
            r = push_next("start·" + ev["reason"])
            if r.get("ok"):
                _state["last_push_ts"] = time.time()
                _save()
            r["msg"] = r.get("msg") or (
                f"已启动并补位 (可用 {len(ev['usable'])}/{ev['needed']})"
                if r.get("ok") else "")
            return r
        return {"ok": True,
                "msg": f"已启动 (可用 {len(ev['usable'])}/{ev['needed']} 达标)"}
    if action == "stop":
        _state["running"] = False
        _save()
        log_ev("", "stopped", "")
        return {"ok": True, "msg": "已停止"}
    if action == "push_next":
        return push_next(reason="manual")
    if action in ("clear_err", "clear_errors"):
        _state["push_err"] = {}
        _save()
        return {"ok": True}
    if action == "refresh_now":
        conf = get_conf()
        res, err, _ = mgmt("/auth-files/refresh?all=true", {})
        if err:
            return {"ok": False, "err": err}
        rs = (res or {}).get("results") or []
        ok = sum(1 for r in rs if r.get("success"))
        log_ev("", "refreshed", f"手动全量刷新 {ok}/{len(rs)}")
        return {"ok": True, "msg": f"刷新 {ok}/{len(rs)} 成功"}
    return {"ok": False, "err": "unknown action"}


EV_LABEL = {
    "pushed": "推送入池", "push_failed": "推送失败",
    "started": "启动", "stopped": "停止",
    "refreshed": "凭证刷新", "refresh_failed": "刷新失败",
    "queue_empty": "预备为空", "tick_error": "tick 错误",
    "queued_remote": "投喂远程",
}


def _iso(ts):
    return datetime.fromtimestamp(ts).strftime(
        "%Y-%m-%dT%H:%M:%S") if ts else ""


def status():
    conf = get_conf()
    accs = _load_accs() or []
    is_remote = conf.get("mode") == "remote"
    r_url, r_pool, r_key = _remote_conf()
    remote_info = {"url": r_url or None, "pool": r_pool or None,
                   "key_set": bool(r_key), "reachable": None,
                   "err": _state.get("remote_err")}
    r_status, r_items = None, None
    if is_remote:
        st, j, err = _remote_status()
        remote_info["reachable"] = err is None
        if err:
            remote_info["err"] = err
        else:
            r_status = j or {}
            remote_info["running"] = r_status.get("running")
            remote_info["conf"] = r_status.get("conf")
        st, j, err = _remote_queue()
        if err is None and isinstance(j, dict):
            r_items = j.get("items") or j.get("queue") or []
        elif isinstance(j, list):
            r_items = j
    pool = pool_accounts()
    capacity, trig = None, {"quota": 0, "deg": 0, "err": 0, "tmr": 0}
    if is_remote and r_status is not None:
        rc = r_status.get("conf") or {}
        capacity = {"rpm": r_status.get("rpm"),
                    "needed": r_status.get("needed"),
                    "usable": r_status.get("usable"),
                    "deficit": r_status.get("deficit"),
                    "capacity_rpm": rc.get("capacity_rpm"),
                    "source": "remote"}
    elif pool is not None:
        ev_res = eval_pool(conf, pool)
        capacity = {"rpm": round(ev_res["rpm"], 1),
                    "needed": ev_res["needed"],
                    "usable": len(ev_res["usable"]),
                    "deficit": ev_res["deficit"]}
        for a in pool:
            v = ev_res["verdicts"][a["name"]]
            a["usable"], a["reasons"] = v["ok"], v["reasons"]
            a["probe_err"] = _state["probe_err"].get(a["name"])
            for r in v["reasons"]:
                if r.startswith("额度"):
                    trig["quota"] += 1
                elif r in ("冷却", "失效"):
                    trig["deg"] += 1
                elif r.startswith("错误率"):
                    trig["err"] += 1
                elif r.startswith("在池"):
                    trig["tmr"] += 1
    by_name = {a["name"]: a for a in (pool or [])}
    queue = []
    sent = _state["remote_sent"]
    pending_names = set()
    if is_remote:
        # 远程 pending 队列项 (可删)
        for it in (r_items or []):
            fn = it.get("filename") or it.get("name") or ""
            pending_names.add(fn)
            queue.append({"id": it.get("id"), "src": "remote",
                          "email": it.get("email") or canon_account(fn),
                          "filename": fn, "status": "remote_pending",
                          "ts": _iso(it.get("added_ts") or
                                     it.get("created_at") or it.get("ts")),
                          "error": it.get("error") or it.get("err")})
        # 对账: 已投喂但不在远程 pending → 已进池的标 cpa=yes
        # 并从 creds 清掉该空间条目 (账号重 ready 时不会把
        # 已消费凭证又投一遍); 没进池的清 sent 允许重投
        # (远程队列被删/清时自愈)
        dirty = False
        for a in accs:
            if not a.get("cred") and not a.get("creds"):
                continue
            ents = (list(a["creds"].items()) if a.get("creds")
                    else [((a.get("cred_ws") or
                            a.get("space_ws") or ""),
                           {"file": a.get("cred_file")})]) \
                if (a.get("cred") or a.get("creds")) else []
            for ws, ent in ents:
                key = _sent_key(a, ws or None)
                rec = sent.get(key)
                if not rec:
                    continue
                fn = ent.get("file") or ""
                if not fn or fn in pending_names:
                    continue
                if by_name.get(fn) is not None:
                    if a.get("cpa") != "yes":
                        a["cpa"] = "yes"; a["cpa_at"] = _now()
                    if a.get("creds"):
                        a["creds"].pop(ws, None)
                    dirty = True
                else:
                    del sent[key]
        if dirty:
            _save_accs(accs)
            _save()
    for a in accs:
        if not (a.get("cred") and _alive(a)):
            continue
        st = a.get("cpa") or ""
        if st not in ("ready", "yes"):
            continue
        fn = a.get("cred_file") or ""
        pa = by_name.get(fn)
        em = a.get("email") or ""
        if is_remote and st == "ready" and fn and fn in pending_names:
            continue            # 远程行已代表, 不重复显示
        row = {"id": a["id"], "src": "local", "email": em,
               "filename": fn,
               "status": "pending" if st == "ready" else "pushed",
               "ts": a.get("cred_at") or "",
               "pushed_ts": _local_ts(a.get("cpa_at") or ""),
               "error": _state["push_err"].get(em),
               "live": bool(pa)}
        if is_remote and st == "ready":
            if fn and fn in pending_names:
                row["status"] = "remote_pending"
            elif _sent_key(a) in sent:
                row["status"] = "remote_sent"
        if st == "yes" and pa is not None and not pa.get("usable"):
            row["live_reasons"] = pa.get("reasons") or []
        queue.append(row)
    counts = {"pending": sum(1 for r in queue
                             if r["status"] in ("pending", "remote_pending")),
              "pushed": sum(1 for r in queue if r["status"] == "pushed"),
              "failed": len(_state["push_err"])}
    conf_out = {k: v for k, v in conf.items()
                if k not in ("probe_api_key", "has_key",
                             "remote_key", "remote_url", "remote_pool")}
    conf_out["cpa_url"] = conf["addr"]
    conf_out["key_set"] = conf["has_key"]
    conf_out["api_key_set"] = bool(conf["probe_api_key"])
    conf_out["remote_url"] = conf.get("remote_url") or ""
    conf_out["remote_url_eff"] = r_url or ""
    conf_out["remote_pool"] = conf.get("remote_pool") or ""
    conf_out["remote_pool_eff"] = r_pool or ""
    conf_out["remote_key_set"] = bool(conf.get("remote_key"))
    events = [{"ts": _iso(e.get("ts")), "kind": e.get("event") or "",
               "msg": "%s%s%s" % (
                   EV_LABEL.get(e.get("event"), e.get("event") or ""),
                   (" · " + e["email"]) if e.get("email") else "",
                   (" · " + e["detail"]) if e.get("detail") else "")}
              for e in _state["events"][:15]]
    running = _state["running"]
    pool_err = None
    if is_remote:
        pool_err = remote_info.get("err") if remote_info.get("reachable") is False else None
    elif pool is None:
        pool_err = _state.get("pool_err") or None
    return {"running": running,
            "mode": conf.get("mode") or "local",
            "remote": remote_info,
            "conf": conf_out,
            "addr": conf["addr"] or None,
            "pool_err": pool_err,
            "capacity": capacity,
            "pool_n": len(pool or []), "pool": pool or [],
            "queue_n": counts["pending"],
            "queue": queue, "counts": counts,
            "events": events,
            "ts": trig,
            "last_refresh": _iso(_state["refresh_ts"]) or None,
            "logs_err": _state.get("logs_err")}
