# PAT 检验 — 接口与判定说明

本文档汇总「拉号进空间 → 创建 PAT 探针 → 判定账号等级」的完整链路。
所有调用都在 **Roxy 窗口内已登录的 `chatgpt.com` 页面**里通过 CDP `page.evaluate` 执行，
不是后端直连——Cookie 会话、CF 指纹、oai-* 头都由真实浏览器天然携带。

代码位置：`server.py` 1769–2380 行（`_INVITE_JS` / `_PAT_PROBE_JS` /
`_PAT_DELETE_JS` / `_pat_verdict` / `_pat_worker`）。

---

## 0. 流程总览

```
母号窗 (chatgpt.com 登录态)
  │  1) 换 workspace token
  │  2) POST /backend-api/accounts/{ws}/invites   ← 批量拉子号
  ▼
子号窗 (各自代理 + 指纹)
  │  3) 刷新 chatgpt.com → 自动成为成员 (或 API accept 兜底)
  │  4) 换同一空间的 workspace token
  │  5) POST /backend-api/wham/auth-credentials  ← PAT 探针
  │  6) 按响应判定 good / low；真建出 PAT 则立即删除
  ▼
账号记录: a.pat = good|low|unknown:*|窗口未登录...
```

---

## 1. 通用前置：换 workspace token

所有空间级操作（邀请、退空间、建 PAT）都要求请求带**目标空间的 token**。
子号/母号窗口当前停在哪个空间无所谓，`exchange_workspace_token`
返回的 `accessToken` 就是该空间声明的 AT：

```js
const r = await fetch('/api/auth/session?exchange_workspace_token=true'
    + '&workspace_id=' + wsId + '&reason=setCurrentAccount',
    {credentials: 'include'});
const tok = (await r.json()).accessToken;
```

这就是 ChatGPT 前端"切换 workspace"时调的同一个接口。

请求头约定（空间级接口通用）：

| Header | 取值 |
|---|---|
| `authorization` | `Bearer <workspace token>` |
| `chatgpt-account-id` | 目标 `workspace_id`（注意：**是 ws id，不是个人 account_id**） |
| `content-type` | `application/json` |
| `credentials` | `include`（携带 Cookie 会话） |

列空间 / 看自己在哪些空间：

```js
const acc = await (await fetch('/backend-api/accounts/check/v4-2023-04-27',
    {credentials: 'include', headers: H})).json();
// acc.accounts[*].account: {account_id, name, structure: 'workspace'|'personal',
//                            account_user_role, plan_type, ...}
```

---

## 2. 母号邀请接口（`_INVITE_JS`）

```
POST /backend-api/accounts/{wsId}/invites
```

一次请求可拉**多个**子号（`email_addresses` 是数组），批量邀请直接一把发完。

```js
const body = {
    email_addresses: emails,          // ["a@x.com", "b@y.com", ...]
    flow_id:       uuid(),            // 每次新 uuid
    role:          'standard-user',
    resend_emails: true,
    submission_id: uuid(),            // 每次新 uuid
    seat_type:     seatType           // 见下
};
const r = await fetch('/backend-api/accounts/' + wsId + '/invites', {
    method: 'POST', credentials: 'include',
    headers: {authorization: 'Bearer ' + tok,
              'chatgpt-account-id': wsId,
              'content-type': 'application/json'},
    body: JSON.stringify(body)});
```

**seat_type 探测**（发出前先查空间计划类型）：

- 空间 `plan_type` 含 `usage_based` 或 `is_usage_based_seat_enabled === true`
  → `seat_type: 'usage_based'`（codex 用量计费席）
- 固定席位空间 → `'default'`（标准席）或 `'prolite'`（高级席）
- PAT 检验任务固定传 `usage_based`

**响应**：

| 情况 | 处理 |
|---|---|
| `200` | body 里 `already_member_emails` 列出已是成员的邮箱；其余为新发邀请 |
| `401` / body 含 `token_expired` | 母号 token 过期 → 刷新母号页重取 AT，最多 3 次 |
| `401` 持续 / `no_token` | 母号会话失效 → 任务终止，需在母号窗重新登录 |
| 其他非 200 | 批量邀请失败，任务终止 |

---

## 3. 子号加入空间

主路径：**子号窗口刷新 `chatgpt.com` 即自动落成员身份**——
母号邀请发出后，子号下次拉取 session/accounts 时就在 `accounts` 里
能看到该 workspace，无需显式 accept。

### 查看订阅接口（实测确认）

```
GET /backend-api/subscriptions?account_id={ws_id}
```

- `account_id` 与 `organization_id` 二选一必填；`organization_id` 填 ws id 实测 500。
- **普通成员 token 即可查**（不需 owner）——子号接受邀请前后都能读。
- 返回该空间的订阅 entitlement：`subscription_plan`（如 `chatgptteamplan`）、
  `has_active_subscription`、`expires_at`/`renews_at`、`billing_period`、
  `billing_currency`、`is_delinquent` 等——判断空间计划是否活着用这一条就够。
- 用个人 free 号的 `account_id` 查 → `404 No subscription found for account`。

### 空间挂起邀请列表（实测确认）

```
GET /backend-api/accounts/{ws_id}/invites
→ 200 {"items":[{"id":"…","email_address":"…","role":"standard-user",
                 "status":5,"seat_type":"usage_based","created_time":"…"}]}
```

**路径里必须是空间 id**：填子号 personal `account_id`
→ `401 "Must use workspace account for this operation"`。
成员 token（个人 AT）就能读这个队列——可配合
`POST /backend-api/accounts/{ws}/invites/{invite_id}/accept` 走纯 API 接受。

> ⚠️ 已知缺陷：`_ACCEPT_INVITE_JS` 的 list 步骤用的是 personal `pid`
> （`accounts/{pid}/invites`），实测该路径 401，即"列邀请"一步实际拿不到——
> 兜底目前只能靠拿到 invite_id 后直打 accept。改进方向：母号侧读
> `accounts/{ws}/invites` 队列按 email 取 invite_id 传给子号 accept。

兜底路径（`_ACCEPT_INVITE_JS`，用于邀请没落地的场景）：

```js
// 1) 拿个人 AT，查 accounts/check 拿自己的 personal account_id (pid)
GET /api/auth/session                        → accessToken
GET /backend-api/accounts/check/v4-2023-04-27 → accounts[*].account
    取 structure === 'personal' 的 account_id 作为 pid

// 2) 列 pending 邀请 —— 注意: 路径必须空间 id, personal pid 会 401
GET /backend-api/accounts/{ws}/invites       → {items: [{id, email_address, status}]}

// 3) 逐个接受（两种路由都试）
POST /backend-api/accounts/{pid}/invites/{invite_id}/accept   body: {}
POST /backend-api/invites/{invite_id}/accept                  body: {}
```

**子号主动申请加入**（备用方向，实测可用）：

```
POST /backend-api/accounts/{wsId}/invites/request   body: {}
→ 200 {"success":true, "workspace_full":false}
```

注意：

- 需带 `chatgpt-account-id` 头，值是**子号自己的** `chatgpt_account_id`
  （从 AT JWT 的 `https://api.openai.com/auth.chatgpt_account_id` claim 取）。
- 返回 200 仅代表**申请已送达**，躺母号后台 Requests 列表等批准，不是直接进。
- **手机号注册且未绑邮箱的号走不了这条路**：`400 User email is required`——
  接口从账号档案取申请人邮箱，手机 OTP 注册的号档案里没有邮箱。

---

## 4. PAT 创建探针（`_PAT_PROBE_JS`）

```
POST /backend-api/wham/auth-credentials
body: {"name": "pat-probe-<ts>", "ttl": 2592000}   // ttl = 30 天, int 秒
```

```js
const s = await fetch('/api/auth/session?exchange_workspace_token=true'
    + '&workspace_id=' + wsid + '&reason=setCurrentAccount',
    {credentials: 'include'});
const tok = (await s.json()).accessToken;
if (!tok) return {status: 0, code: 'no_token'};

const r = await fetch('/backend-api/wham/auth-credentials', {
    method: 'POST', credentials: 'include',
    headers: {authorization: 'Bearer ' + tok,
              'chatgpt-account-id': wsid,
              'content-type': 'application/json'},
    body: JSON.stringify({name: 'pat-probe-' + Date.now(), ttl: 2592000})});

const raw = await r.text();          // 先存原文再解析, 判定排障要用
let j = null; try { j = JSON.parse(raw); } catch (e) {}
const d = (j && j.detail) || {};
return {
    status: r.status,
    code: d.code || (d.error && d.error.code)
        || (j && j.error && j.error.code) || null,
    msg:  (d.message || ...) 截 200,
    raw:  raw 截 600,
    cred: j.credential_id || j.credential?.id    // 真建出来才有
};
```

**wham** = codex 的 auth-credentials 服务前缀。`name` 必填，`ttl` 必填 int 秒。

真建成功（200）时**立即删除**不留活 PAT（`_PAT_DELETE_JS`）：

```
DELETE /backend-api/wham/auth-credentials/{credential_id}
headers: authorization + chatgpt-account-id (同上)
```

---

## 5. 响应判定（`_pat_verdict`）

```python
def _pat_verdict(status, code):
    if status == 200:                                   return "good_created"
    if code == "access_token_creation_disabled":        return "low"
    if code and ("verification" in code or "mfa" in code.lower()
                 or "required" in code):                return "good"
    return None    # 未知 → 刷新重试, 3 次后 unknown:<status>/<code>
```

| 上游响应 | status | code | 判定 | 含义 |
|---|---|---|---|---|
| 建 PAT 成功 | 200 | — | `good_created`→记 `good` | 真能建，删除临时 PAT 后标良好 |
| 手机/身份验证 | 401 | `phone_verification_required` 等 `*verification*`/`*required*`/`*mfa*` | `good` | 号有资格，过验证即可建 |
| PAT 功能禁用 | 403 | `access_token_creation_disabled` | `low` | 账号级禁用（实测与注册方式/风控标记相关，**不是空间级**） |
| 未登录 | 0 | `no_token` | `窗口未登录` | 窗口里没登录态 |
| 其他 | 任意 | 任意 | `unknown:<status>/<code>` | 原始响应已打日志，按 `raw` 人工判 |

**判定逻辑要点**：`verification`/`required` 类 4xx 算 good——
因为"要过验证"本身就说明接口认可了该号的建 PAT 资格，只是差一步验证；
而 `access_token_creation_disabled` 是硬性禁用，算低级号。

worker 每轮把 `raw`（脱敏后）打进 PAT 日志：
`token|credential|secret|value` 的 JSON 值截断 `***`，`sk-*` 串遮蔽——
活 PAT 不落明文日志。

---

## 6. 实测响应样例（同空间 My Team `54c5970c-…`，三个号三种命）

```jsonc
// jackqzz1 / kokeraasmita —— 低级
403 {"detail":{"message":"Access token creation is temporarily disabled",
               "code":"access_token_creation_disabled"}}

// 261021-264 —— 良好 (差手机验证)
401 {"detail":{"message":"Phone verification required",
               "code":"phone_verification_required"}}

// 结论: access_token_creation_disabled 是账号级标记,
//       同空间不同号返回不同 → 排除"空间管理员禁建"的解释
```

---

## 7. 任务入口（本系统 API）

| 端点 | 说明 |
|---|---|
| `POST /api/accounts/pat-check` `{ids}` | 启动 PAT 检验任务（`_pat_worker`） |
| `GET  /api/accounts/pat/status` | 任务日志 + 每号结果 |
| `POST /api/accounts/pat-check/stop` | 手动停止 |

前置依赖：`settings.mother_window`（母号 Roxy 窗口名）+
`settings.mother_workspace`（目标空间 id），从设置页/母号页配置。

子号侧自动做的：确保代理绑定 → `_roxy_open_for` 开窗 → CDP 连接 →
找 `chatgpt.com` 页（`_find_cgpt_page`）→ 刷新导航 → evaluate 探针，
未知响应最多重试 3 次。结果落 `a.pat` / `a.pat_at` / `a.ws_id`，
并顺带回填 `a.reg=yes`（能探到 verdict 即证明窗口登录态存在）。
