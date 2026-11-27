# Better Stack 状态监控部署指南

> 项目：**迷宫冒险** ｜ 线上域名：`maze-game-apiserver.onrender.com` ｜ 平台：Render

本文档说明如何为本项目接入 Better Stack 的两种监控方式，并创建对外状态页。

---

## 0. 前置说明

服务端已内置两个公开健康端点（注册在所有中间件与 catch-all 路由之前）：

| 端点 | 返回 | 说明 |
| --- | --- | --- |
| `GET /health` | `200` + JSON `{status, uptimeSeconds, timestamp}` | 进程存活、运行秒数、时间戳；不依赖数据库 |
| `GET /health/ping` | `200` + 文本 `pong` | 极简存活探针 |

两个端点均**不鉴权、不受 CSRF / 限流 / API 自定义规则影响**，且不泄露任何密钥。

示例：

```bash
curl -i https://maze-game-apiserver.onrender.com/health
# HTTP/2 200
# {"status":"ok","uptimeSeconds":1234,"timestamp":"2026-11-27T14:00:00.000Z"}

curl -i https://maze-game-apiserver.onrender.com/health/ping
# HTTP/2 200
# pong
```

---

## 1. 方式 A：HTTP 监控（推荐主用）

Better Stack 的 Uptime 监控会主动定期请求你的 URL，按状态码 / 响应时间判定在线状态。

### 1.1 控制台操作

1. 登录 <https://betterstack.com/> → **Uptime** → **Add monitor** → **HTTP**。
2. 填写：
   - **URL**：`https://maze-game-apiserver.onrender.com/health/ping`
   - **Check frequency**：`1 minute`（1 分钟）
   - **Expected status code**：`200`
   - **Request timeout**：默认或 `10s`
3. 保存后等待首次检查，确认状态为 **Up**。

> 说明：优先用 `/health/ping`（纯文本、零依赖），避免 JSON 解析或数据库状态影响判定。

### 1.2 可选：监控数据库依赖

若需要把数据库连通性也纳入监控，可另加一个监控项指向 `/api/server-status`（该端点可能依赖数据库），但不要替换 `/health/ping`，否则数据库抖动会造成误报。

---

## 2. 方式 B：Heartbeat（推送式监控）

适用于 Render 冷启动、出站请求更稳定等场景：由服务端**主动上报**给 Better Stack。

### 2.1 控制台操作

1. Better Stack → **Heartbeats** → **New heartbeat**。
2. 创建后复制上报 URL（形如 `https://uptime.betterstack.com/api/v1/heartbeat/xxxxxxxx`）。
3. **Grace period（宽限期）必须大于上报间隔**——这是硬性要求：
   - 本服务默认上报间隔 **60 秒**（`BETTERSTACK_HEARTBEAT_INTERVAL_MS`）。
   - 因此 Grace period 建议设为 **2 分钟（120 秒）或更长**。
   - 若把间隔改为 30 秒，Grace period 至少 1 分钟；若间隔 5 分钟，Grace period 至少 10 分钟。
   - 宽限期 ≤ 上报间隔会导致偶发网络抖动被误判为宕机并触发告警。

### 2.2 服务端配置

在 Render 服务的 **Environment** 中添加变量（不要写入仓库）：

| 变量名 | 值 | 说明 |
| --- | --- | --- |
| `BETTERSTACK_HEARTBEAT_URL` | 第 2.1 步复制的完整 URL | 留空则不上报 |
| `BETTERSTACK_HEARTBEAT_INTERVAL_MS` | `60000` | 毫秒；留空默认 60000 |

行为：
- 服务启动后**立即上报一次**，随后按间隔定时上报。
- 上报失败只写日志（`[Heartbeat] 上报失败…`），**不影响主服务**。
- 定时器使用 `unref()`，不会阻止进程退出。

本地 `.env.example` 已包含这两个变量的模板，复制为 `.env` 后填写即可（`.env` 不应提交）。

---

## 3. 创建状态页并绑定监控

1. Better Stack → **Status pages** → **Create status page**。
2. 填写名称（如 `迷宫冒险服务状态`）、自定义域名（可选，如 `status.yourdomain.com`）。
3. 在 **Monitors** 区域勾选第 1 节创建的 HTTP 监控和/或第 2 节的 Heartbeat。
4. 保存后得到状态页地址（形如 `https://<your-slug>.betterstackstatus.com`）。
5. 把该地址替换到首页 `public/index.html` 中的状态页链接占位符：
   ```html
   <!-- TODO: 替换为 Better Stack 实际状态页地址 -->
   <a href="https://YOUR-STATUS-PAGE.betterstackstatus.com" target="_blank" rel="noopener">服务状态</a>
   ```
   当前该链接为**占位符**，需在第 6 阶段状态页创建后由项目所有者替换。

---

## 4. 验证命令

### 4.1 本地

```bash
# 启动服务
npm start

# 另开终端验证
curl -i http://localhost:234/health
curl -i http://localhost:234/health/ping
```

期望：`/health` 返回 `200` 且 JSON 含 `status`/`uptimeSeconds`/`timestamp`；`/health/ping` 返回 `200 pong`。

### 4.2 线上（部署生效后）

```bash
curl -i https://maze-game-apiserver.onrender.com/health
curl -i https://maze-game-apiserver.onrender.com/health/ping

# 只看状态码
curl -s -o /dev/null -w '%{http_code}\n' https://maze-game-apiserver.onrender.com/health
```

### 4.3 Heartbeat 生效验证

- 配置 `BETTERSTACK_HEARTBEAT_URL` 并重启后，查看服务日志是否出现 `[Heartbeat] 已启动…`。
- 在 Better Stack Heartbeat 详情页确认最近一次 Ping 时间持续更新。

---

## 5. Token / URL 安全说明

- **Heartbeat URL 内含写入令牌**，等同于凭据：
  - 只能存放在服务端环境变量（Render Environment / 本地 `.env`）中。
  - **绝不写入前端代码、不提交到 Git 仓库**。
  - 若不慎泄露，立即在 Better Stack 控制台 **Rotate / 重建 Heartbeat**，旧 URL 随即失效。
- `.env.example` 只放**空的占位变量名**，不含任何真实 token。
- 本项目 `.gitignore` 已忽略 `*.html` 与 `public/`，但**不忽略 `.env`**（当前无 `.env` 文件）；请自行确认 `.env` 未被 `git add`，或在 `.gitignore` 中追加 `.env` 一行（本指南未擅自修改 `.gitignore`）。
- Better Stack API Token（用于自动化创建监控）同样只存环境变量，不写入任何源码或文档。
- 公开状态页不应展示敏感端点；本方案只绑定 `/health` 与 Heartbeat，不暴露管理接口。

---

## 6. 已知限制 / 待办

- 状态页 URL 当前为占位符，需第 6 阶段（用户登录 Better Stack 控制台）创建后替换。
- `public/` 被 `.gitignore` 忽略，首页链接的改动为**本地改动**，不会随本次提交推送；如需上线，请项目所有者决定将 `public/index.html` 纳入版本控制或在部署流程中注入该链接。
