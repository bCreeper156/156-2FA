# 156-2FA API 文档

156-2FA 采用**前后端分离**架构：后端是一套无状态 REST 接口，前端（`web/`）是纯静态页面，
两者通过 HTTP 通信，可同进程部署（默认的桌面模式），也可完全分离部署。

- **基础路径**：`<服务地址>/api`
- **数据格式**：请求与响应均为 JSON（`UTF-8`），导出接口除外（纯文本）
- **机器可读规范**：`GET /api/openapi.json`（OpenAPI 3.1）
- **在线文档页**：`GET /api/docs`（页面本体是 `web/apidocs.html`，可由任意静态服务器托管）

> 安全边界：接口**只返回已计算好的验证码**，Secret 与用户口令永不出现在任何响应里。

---

## 目录

1. [鉴权](#1-鉴权)
2. [接口一览](#2-接口一览)
3. [接口详解](#3-接口详解)
4. [数据模型](#4-数据模型)
5. [错误约定](#5-错误约定)
6. [远程接入：让软件连接远程 API](#6-远程接入让软件连接远程-api)
7. [独立部署前端](#7-独立部署前端)
8. [前端调用示例](#8-前端调用示例)

---

## 1. 鉴权

三种方式任选其一：

| 方式 | 适用对象 | 说明 |
| --- | --- | --- |
| `Authorization: Bearer <accessToken>` | 远程客户端 / 第三方 | 不受来源（Host / Origin）限制，令牌由服务端持有者配置 |
| `Cookie: 2fa_frontend=<frontendToken>` | 桌面端内置窗口、同机浏览器 | 每次启动随机生成并下发，受 Host + Origin 白名单保护 |
| URL 参数 `?token=<frontendToken>` | 首次加载 / 同机浏览器 | 命中后服务端会自动下发同名 Cookie |

未通过校验时返回 `403`，响应体统一为 `{"ok": false, "error": "..."}`。

`GET /api/health`、`GET /api/openapi.json`、`GET /api/docs` 为**公开接口**，无需鉴权。

跨域已支持 CORS 预检：`Origin` 受白名单控制（默认允许全部），响应会带
`Access-Control-Allow-Origin` 等头。远程模式使用 Bearer 令牌，不依赖 Cookie。

---

## 2. 接口一览

| 方法 | 路径 | 说明 | 鉴权 |
| --- | --- | --- | --- |
| GET | `/api/health` | 健康检查（用于「测试连接」） | 否 |
| GET | `/api/info` | 服务信息：地址、端口、当前用户 | 是 |
| GET | `/api/accounts` | 列出账户与当前验证码 | 是 |
| POST | `/api/accounts` | 新增账户 | 是 |
| PUT | `/api/accounts/{id}` | 修改账户 | 是 |
| DELETE | `/api/accounts/{id}` | 删除账户 | 是 |
| POST | `/api/import` | 导入 otpauth 链接或二维码图片 | 是 |
| GET | `/api/export` | 导出备份 / otpauth 文本 | 是 |
| POST | `/api/restore` | 从备份或文本批量恢复 | 是 |
| POST | `/api/reset` | 清空全部账户数据 | 是 |
| POST | `/api/bye` | 页面关闭信号 | 是 |
| GET | `/api/openapi.json` | OpenAPI 规范 | 否 |
| GET | `/api/docs` | HTML 文档页 | 否 |

所有接口都支持 `OPTIONS` 预检请求。

---

## 3. 接口详解

以下示例假定：

```bash
BASE="http://127.0.0.1:41234"   # 服务地址，见 /api/info
TOKEN="你的令牌"                  # 远程模式必填；本地同机会话可省略
```

### 3.1 GET /api/health

健康检查，免鉴权，用于连接测试。

```bash
curl "$BASE/api/health"
```

```json
{
  "ok": true,
  "service": "156-2FA",
  "version": "1.0.0",
  "mode": "local",
  "authRequired": true,
  "username": "alice",
  "serverTime": 1761900000.0
}
```

### 3.2 GET /api/info

```bash
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/info"
```

```json
{
  "ok": true,
  "service": "156-2FA",
  "version": "1.0.0",
  "mode": "local",
  "host": "127.0.0.1",
  "port": 41234,
  "username": "alice",
  "address": "127.0.0.1:41234",
  "urls": ["http://127.0.0.1:41234", "http://[::1]:41234"],
  "documentation": "/api/docs",
  "openapi": "/api/openapi.json",
  "static": true,
  "remoteToken": false
}
```

- `urls`：当前监听地址下实际可访问的地址列表（监听 `0.0.0.0` 时会列出全部网卡地址）。
- `remoteToken`：服务端是否已配置 `accessToken`（即是否允许远程客户端访问）。

### 3.3 GET /api/accounts

返回全部账户、当前验证码与剩余秒数，按 `issuer` / `name` 排序。

```bash
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/accounts"
```

```json
{
  "ok": true,
  "address": "127.0.0.1:41234",
  "host": "127.0.0.1",
  "port": 41234,
  "username": "alice",
  "serverTime": 1761900000.0,
  "accounts": [
    {
      "id": 1,
      "name": "GitHub",
      "issuer": "GitHub",
      "createdAt": "2026-09-11T21:00:00Z",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "code": "482 913",
      "remaining": 27,
      "counter": 59384291
    }
  ]
}
```

> 前端用 `serverTime` 与本地时钟的差值校准倒计时，即使用户改过系统时间也不会算错剩余秒数。

### 3.4 POST /api/accounts

新增账户，`secret` 为 Base32 密钥（大小写与空格均可，服务端会归一化）。

```bash
curl -X POST "$BASE/api/accounts" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"GitHub","secret":"JBSWY3DPEHPK3PXP","issuer":"GitHub","algorithm":"SHA1","digits":6,"period":30}'
```

响应：`{"ok": true, "account": {...}}`。缺少 `secret` 返回 `400`。

### 3.5 PUT /api/accounts/{id}

修改账户；字段留空表示不修改，`secret` 留空表示不更换密钥。

```bash
curl -X PUT "$BASE/api/accounts/1" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"GitHub 工作","issuer":"GitHub"}'
```

账户不存在返回 `404`。

### 3.6 DELETE /api/accounts/{id}

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/api/accounts/1"
# {"ok": true}
```

### 3.7 POST /api/import

导入单条 `otpauth://` 链接，或二维码图片 Data URL（服务端解码识别）。

```bash
# 链接
curl -X POST "$BASE/api/import" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"uri":"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"}'

# 二维码
curl -X POST "$BASE/api/import" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"image":"data:image/png;base64,iVBORw0..."}'
```

失败返回 `400`：二维码无法识别、内容不是 2FA 链接、参数缺失等。

### 3.8 GET /api/export

| 参数 | 取值 | 说明 |
| --- | --- | --- |
| `format` | `backup`（默认） | 由当前用户口令保护的加密 JSON |
| `format` | `otpauth` | 每行一个 `otpauth://` 链接的明文文本 |

```bash
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/export?format=otpauth"
```

响应为 `text/plain`，带 `Content-Disposition` 与 `X-Suggested-Filename`；
后者已加入 `Access-Control-Expose-Headers`，跨域调用也能读取文件名。

### 3.9 POST /api/restore

从备份文件或 otpauth 文本批量恢复，自动识别内容类型。

```bash
curl -X POST "$BASE/api/restore" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"content":"{\n  \"version\": 2, ...}","mode":"merge"}'
```

- `mode`：`merge`（默认，合并追加并按密钥去重）或 `replace`（覆盖全部）
- 响应：

```json
{
  "ok": true,
  "result": {"added": 2, "skipped": 1, "invalid": 0, "total": 2, "mode": "merge", "source": "backup"}
}
```

### 3.10 POST /api/reset

清空当前用户的全部账户数据（用户口令本身保留），随后服务端触发宿主的退出回调。

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" "$BASE/api/reset"
```

### 3.11 POST /api/bye

页面 `pagehide` 时发送的信号，仅在服务端启用「空闲自动退出」时生效，用于关闭页面后自动停止服务；
桌面模式会忽略该信号。

---

## 4. 数据模型

### Account（响应）

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | integer | 唯一标识，用于修改 / 删除 |
| `name` | string | 备注名称 |
| `issuer` | string | 发行方 |
| `createdAt` | string | 创建时间（ISO 8601，可选） |
| `algorithm` | string | `SHA1` / `SHA256` / `SHA512` |
| `digits` | integer | 验证码位数，通常 6 |
| `period` | integer | 时间片长度（秒），通常 30 |
| `code` | string | 当前验证码（计算失败时为 `------`） |
| `remaining` | integer | 剩余有效秒数 |
| `counter` | integer | 当前时间片序号 |

> 出于安全考虑，响应中**没有** `secret` 字段。

### AccountInput（新增请求）

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `name` | 是 | 备注名称 |
| `secret` | 是 | Base32 密钥 |
| `issuer` | 否 | 发行方 |
| `algorithm` | 否 | 默认 `SHA1` |
| `digits` | 否 | 默认 `6` |
| `period` | 否 | 默认 `30` |

### AccountUpdate（修改请求）

全部字段可选，缺省即保持原值。

---

## 5. 错误约定

```json
{ "ok": false, "error": "端口 30001 在 127.0.0.1 上已被占用" }
```

| 状态码 | 含义 |
| --- | --- |
| 400 | 参数缺失或不合法（密钥为空、备份版本不支持等） |
| 403 | 来源不在白名单，或令牌无效 |
| 404 | 资源不存在（账户 id 不存在、路径未注册） |
| 500 | 服务端失败（如写盘失败） |

未捕获异常同样返回该结构，前端可直接展示 `error` 字段。

---

## 6. 远程接入：让软件连接远程 API

桌面端既可以连接本机服务（默认），也可以连接**远程 API**。

### 6.1 启动服务端

在持有数据的机器上运行（会提示输入用户名与口令以解锁保险库）：

```bash
# 监听全部网卡的固定端口并指定访问令牌
python main.py serve --host 0.0.0.0 --port 8765 --token your-secret-token

# 不挂载前端页面：纯 API 模式
python main.py serve --host 0.0.0.0 --port 8765 --token your-secret-token --no-static

# 不指定 --token 时会随机生成并写入 data/server.json
python main.py serve --host 0.0.0.0 --port 8765
```

启动后会打印可用地址、接口文档地址与令牌。令牌也可通过环境变量提供（优先级最高）：

```bash
export TOTP_API_TOKEN="your-secret-token"      # Linux / macOS
set TOTP_API_TOKEN=your-secret-token           # Windows CMD
```

### 6.2 客户端连接

打开桌面端「设置 → 连接与 API」：

1. 选择 **远程 API**
2. 填写远程地址（例如 `http://192.168.1.9:8765`，无需写 `/api`）
3. 填入服务端令牌
4. 点 **测试连接**，成功后显示服务端用户名与耗时
5. 点 **应用并返回**

连接配置保存在 `data/server.json`：

```json
{
  "version": 2,
  "mode": "remote",
  "host": "127.0.0.1",
  "port": null,
  "remoteUrl": "http://192.168.1.9:8765",
  "remoteToken": "your-secret-token",
  "accessToken": ""
}
```

切回 **本地服务** 即可恢复本机数据源，两者互不干扰。

> 远程模式建议只在可信网络内使用，或置于 HTTPS 反向代理之后。
> 令牌泄露意味着对方可以获取全部验证码（但拿不到 Secret 明文，因为接口不返回 Secret）。

---

## 7. 独立部署前端

`web/` 目录是纯静态资源，可交给任意静态服务器托管，无需与后端同机：

```nginx
# Nginx 示例：前端静态托管
server {
    listen 8080;
    root /opt/156-2FA/web;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

随后把后端地址告诉前端即可，三种方式任选：

1. 打开的首页拼参数：`http://前端地址/index.html?api=http://后端地址:8765&apiToken=令牌`
2. 在「设置 → 连接与 API」里填写远程地址与令牌（会存入 localStorage）
3. 后端与前端同源部署时无需任何配置，默认走相对路径 `/api`

## 8. 前端调用示例

前端统一通过 `web/api.js` 暴露的 `ApiClient` 访问数据，页面本身不关心数据来源：

```js
// 载入连接配置（本地 / 远程）
await ApiClient.loadConfig();

// 拉取账户与验证码
const data = await ApiClient.listAccounts();
console.log(data.accounts[0].code, data.accounts[0].remaining);

// 新增账户
await ApiClient.addAccount({ name: 'GitHub', secret: 'JBSWY3DPEHPK3PXP', issuer: 'GitHub' });

// 切换到远程 API
await ApiClient.setConfig({ mode: 'remote', remoteUrl: 'http://192.168.1.9:8765', remoteToken: '令牌' });

// 连接测试（桌面端会代为发起，避免浏览器同源限制）
const result = await ApiClient.probe({ remoteUrl: 'http://192.168.1.9:8765', remoteToken: '令牌' });
console.log(result.ok, result.latencyMs);
```

不使用 `ApiClient` 时也可直接调用 HTTP 接口（第三方客户端自行实现即可）。

---

MIT License · Copyright (c) 2026
