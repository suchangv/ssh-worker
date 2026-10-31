# ssh-worker

一个跑在 Cloudflare 边缘上的 VPS 管理面板：在浏览器里维护服务器清单，点开就能拿到真正的 SSH 终端。


- **前端**：静态页面（Workers Static Assets）+ xterm.js，亮色主题，无构建步骤
- **SSH**：`ssh2` 在 Durable Object 里跑，用 `cloudflare:sockets` 直连目标 22 端口（不需要任何跳板机 / 本地软件）
- **鉴权**：Cloudflare Access（Zero Trust）JWT，在 Worker 里用团队 JWKS 本地验签，边缘再兜一层
- **凭据**：AES-256-GCM 加密后存 Workers KV，密钥来自 `APP_SECRET`

```
浏览器 ──HTTPS/WSS(带 Access cookie)──► Worker ──► Durable Object ──TCP──► VPS:22
                                        │              │
                                   Access JWT 验签   ssh2 + PTY
                                        │              │
                                       KV(加密凭据)   主机密钥 TOFU 固定
```

## 功能

| 功能 | 说明 |
| --- | --- |
| 服务器清单 | 名称/备注/主机/端口/用户名/密码或私钥，增删改查 |
| 到期时间 | 手填 `yyyy-MM-dd`（无日期选择器），列表里显示剩余天数，14 天内标黄、过期标红 |
| 前端路由 | `/` 列表、`/s/:id/terminal` 终端，刷新/直链/浏览器前进后退都可用 |
| 文件树 | 终端左侧 SFTP 目录树：懒加载展开、刷新（保留展开状态）、全部收起、复制根路径 |
| 一键 cd | 目录行的 `cd` 按钮把 `cd '<path>'` 粘贴进终端但**不回车**，由你决定是否执行 |
| 文件预览 | 文本（≤512 KB）和图片（≤6 MB）在弹窗里直接看；二进制/超大文件提示改用下载 |
| 文件下载 | 文件行「下载」走 SFTP 流式传输（≤200 MB），带正确的 `Content-Disposition`（中文名安全） |
| Web 终端 | xterm.js + PTY，窗口尺寸同步、粘贴、重连、`Ctrl+Shift+Esc` 关闭 |
| 连接测试 | 一次 SSH 握手 + `exec` 拉取系统信息，返回往返耗时；失败时自动做 TCP 诊断并给出可执行建议 |
| 主机密钥固定 | 首次连接记录 `SHA256:` 指纹，之后指纹变化直接拒绝连接 |
| 身份验证 | Cloudflare Access（当前走 Google 登录，OTP 身份源保留可回滚），可再叠加邮箱白名单 |
| 退出登录 | 顶栏「退出」：同源 iframe 访问 `/cdn-cgi/access/logout` 清 cookie，失败则顶层跳转团队域登出地址 |

不支持：SFTP、端口转发、多会话标签页（一个会话一个 Durable Object，可自行扩展）。

## 你需要的

- Node.js 18+ 与 `cf` CLI（本仓库用 `cf deploy` / `cf dev` 部署，也兼容 `wrangler`）
- 一个 Cloudflare 账号 + 已接入的域名（Access 应用只能挂在自有域名的 hostname 上，`*.workers.dev` 不支持）

> **目标 VPS 必须能从公网访问**：Workers 的 `connect()` 只允许连公网地址，私有网段（10/8、192.168/16 等）会被运行时拒绝。

## 部署

### 1. 建 KV

```bash
cf kv namespaces create --title ssh-worker-servers
# 把返回的 id 填进 wrangler.jsonc 的 kv_namespaces[0].id
```

### 2. 生成凭据加密密钥

```bash
printf 'APP_SECRET=%s\n' "$(openssl rand -base64 32)" > .env.production
```

`.env.production` 只放 secret；`ACCESS_*` 等非敏感变量写在 `wrangler.jsonc` 的 `vars` 里。

### 3. 创建 Access 应用（先建应用，拿到 AUD 再部署）

```bash
# 一次性 PIN 登录 + 只允许自己
cf zero-trust access applications create \
  --name ssh-worker \
  --domain ssh.example.com \
  --type self_hosted \
  --session-duration 24h

cf zero-trust access policies create \
  --name "only me" \
  --decision allow \
  --include '[{"email":{"email":"you@example.com"}}]'
```

把策略挂到应用上（`applications create` 也支持直接带 `--policy`，按 CLI 版本选一种）：

```bash
cf zero-trust access applications policies create <APP_ID> --policy-id <POLICY_ID>
```

从 `cf zero-trust access applications list` 里取 `aud`。

### 4. 填配置并部署

项目里有两份配置，必须保持一致（`cf` 只读 `cloudflare.config.ts`，`wrangler` 只读 `wrangler.jsonc`）：

- `cloudflare.config.ts` —— `cf deploy` / `cf dev` 使用（`defineWorker` + `bindings.kv` / `bindings.durableObject` / `bindings.secret`）
- `wrangler.jsonc` —— `wrangler dev` / `wrangler deploy` 使用

项目里的 `cloudflare.config.ts` 不含任何个人信息，真实值从环境变量读：

```bash
cp .env.example .env.deploy   # 填域名 / KV id / 团队域 / AUD / 白名单
```

```bash
npm run deploy                # = 读取 .env.deploy 后执行 cf deploy
```

`APP_SECRET` 用 `bindings.secret()` 声明，具体值只从 `--secrets-file`（`.env.production`）读，不落库。

```bash
cf deploy --secrets-file .env.production
```

`cf deploy` 会读 `cloudflare.config.ts`，上传 Worker、创建 Durable Object、同步 KV/变量/密钥、上传静态资源并绑定自定义域名。之后的更新直接 `cf deploy` 即可（密钥已存在时会复用）。

> 注意：如果项目里没有 `cloudflare.config.ts`，`cf deploy` 会把它当成静态站点自动生成配置，**丢掉了 KV/DO/变量**。所以这个文件必须提交进仓库。

### 5. 验证

打开 `https://ssh.example.com`，应当被 Access 拦到登录页；登录后能看到面板。

```bash
curl -sI https://ssh.example.com | grep -i location   # 未认证时应 302 到 cloudflareaccess.com
curl -s https://ssh.example.com/api/me               # 未认证时应 401
```

## 本地开发

```bash
cp .dev.vars.example .dev.vars   # 填 APP_SECRET，DEV_AUTH_BYPASS=true
cf dev                           # 或 npm run dev（等价于 wrangler dev）
```

本地开发时 `APP_SECRET` 必须是和线上不同的随机值；`DEV_AUTH_BYPASS=true`（只在 `.dev.vars` 里，已被 .gitignore 忽略）让 `/api/me` 直接返回 `dev@localhost`。

> `wrangler dev` 会把请求 URL 改写成 Worker 的自定义域名，所以不能靠 host 判断"是不是本地"。现在的规则是：**只有没经过 Cloudflare 边缘（请求里没有 `cf-ray`）且 `DEV_AUTH_BYPASS=true` 时才放行**。线上请求必然带 `cf-ray`，因此这个开关在生产环境永远不生效。

`DEV_AUTH_BYPASS=true` 只在请求 host 是 `localhost` / `127.0.0.1` 时生效，生产域名上永远走 Access 验签。

注意：本地 workerd 不允许连回环地址，所以本地无法直连 `127.0.0.1:22`；测真机请用一台公网 VPS（或任意公网 SSH 服务）。

## 安全设计

- **两级鉴权**：边缘 Access 应用 + Worker 内 RS256 验签（团队 JWKS，`aud`/`iss`/`exp` 全查）。即使有人误删 Access 应用，API 也会返回 500/401 而不是放开。
- **票据**：WebSocket 升级前服务器签发 60 秒 HMAC 票据，Durable Object 只认票据，不碰 Access 的 JWKS。
- **服务令牌**：Access Service Token 也能通过（记为 `service:<client_id>`），方便 CI / 脚本调用。注意策略必须是 `decision: non_identity`，用 `allow` 时 Access 不会把服务令牌当作独立身份：

```bash
cf zero-trust access policies create --name "ci" --decision non_identity \
  --include '[{"service_token":{"token_id":"<TOKEN_ID>"}}]'
```

- **CSRF**：非 GET 请求要求同源 `Origin` + `x-csrf: 1` 头（跨站无法伪造，会触发预检）。
- **凭据**：`AES-256-GCM`，随机 IV，`v1.` 前缀版本化，只在 Durable Object 内存里解密；列表接口永不返回密文。
- **主机密钥**：首次连接信任并固定（TOFU），之后指纹不一致直接断开；指纹单独存 `hostkey:<id>`，删除服务器会一起清掉。
- **展示层**：严格 CSP（只允许 jsdelivr 提供 xterm）、`frame-ancestors 'none'`、`no-store`。

## 常用操作

```bash
# 看当前谁在访问（登录后浏览器里是邮箱；服务令牌是 service:<id>）
curl -s https://ssh.example.com/api/me \
  -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET"

# 列出服务器（密文永不出现在响应里）
curl -s https://ssh.example.com/api/servers -H "CF-Access-Client-Id: ..." -H "CF-Access-Client-Secret: ..."

# 给某台机器做连接测试
curl -s -X POST https://ssh.example.com/api/servers/<id>/probe \
  -H "CF-Access-Client-Id: ..." -H "CF-Access-Client-Secret: ..." \
  -H "x-csrf: 1" -H "content-type: application/json" -d '{}'
```

## 连不上时怎么排查

"连接测试"失败会顺带做一次裸 TCP 探测，结果直接显示在弹窗里：

| 探测结果 | 含义 | 下一步 |
| --- | --- | --- |
| TCP 连接 10 秒内没有建立 | 对方**丢包**，SYN 被防火墙/安全组丢弃 | 检查 `ss -ltnp`、ufw/firewalld、云厂商安全组；如做了来源白名单，放行 Cloudflare 出站网段（见 https://api.cloudflare.com/client/v4/ips） |
| TCP 被拒绝（RST） | 端口没开 / sshd 未运行 / 防火墙 reject | 确认 sshd 在跑、端口正确 |
| TCP 通但 6 秒无 banner | 端口通但服务不主动说话 | 该端口可能不是 SSH（80/443 之类需要客户端先发请求） |
| 端口返回 HTTP | 打到了网站/面板 | 换回 sshd 端口 |
| 收到 SSH banner 但握手失败 | 网络没问题，是算法或认证 | 检查 sshd 的 `Ciphers`/`KexAlgorithms`，以及账号凭据 |
| 域名解析到 Cloudflare IP | 橙云代理只转发 HTTP/HTTPS，22 端口必失败 | DNS 改成「仅 DNS」，或直接填源站 IP |

另外浏览器端也会把 `诊断：` 开头的逐条建议直接打在终端里。

## 前端路由

| 路径 | 视图 | 说明 |
| --- | --- | --- |
| `/` | 服务器列表 | 卡片上的地址和「连接」都是真链接（可中键新开标签） |
| `/s/:id/terminal` | 终端 | 直达链接，刷新后自动重连；`/s/:id` 也接受 |

- 用 History API（`pushState`/`popstate`），离开终端路由会自动断开 SSH 会话
- 需要 SPA 回退：`assets.not_found_handling = "single-page-application"`（两份配置里都已设置），否则刷新 `/s/...` 会 404
- 删除当前正在查看的服务器会 `replaceState` 回列表，不留死链

## 终端页

顶栏从左到右：**返回**（`←`，Esc 同效）· 服务器名 + `user@host:port` · 状态灯 · **握手**耗时（WS 到 PTY ready 的真实毫秒数，Durable Object 侧计时）· **RTT**（每 5s ping/pong 的浏览器↔边缘往返）· 会话时长 · 字号 A−/A+（记忆在 localStorage）· 复制选中 · 粘贴 · 重连 · 断开。

底栏是快捷键提示和最后一条状态消息（banner、主机密钥固定、错误诊断都在这里滚动）。

## 文件管理器

- 走 SSH 的 **SFTP 子系统**（`client.sftp()`），首次展开时才创建，不支持 SFTP 的服务器会在树里提示
- 根目录用 `sftp.realpath(".")` 解析成真实路径，界面上显示 `~ /home/xxx`
- 懒加载：只有展开的目录才会 `readdir`；目录按「目录优先 + 自然排序」排列，超过 600 项会截断
- 每行操作（悬停出现）：`cd`、`路径`（复制）。`cd` 只发送 `cd '<path>'` 到 PTY，**不带回车**，命令留在提示符后面由你确认
- 路径做了 shell 单引号转义（`'`  →  `'\''`），空格/中文/特殊字符都安全
- 面板宽度 304px，可折叠（状态存 localStorage），折叠/展开会触发 xterm refit

## 数据模型

KV 里的每条记录：

```ts
{
  id, name, note,
  host, port, username,
  authType: "password" | "key",
  secret, passphrase,       // AES-256-GCM 密封
  expiresOn?: "2026-12-31", // 纯日历日，手输，服务端做格式+合法性校验
  createdAt, updatedAt, lastUsedAt
}
```

## 踩坑记录

- **不要把页面容器类名取成 `terminal`**：xterm.js 会给自己的根节点加一个叫 `terminal` 的 class，导致
  `.terminal { position: fixed; inset: 0; z-index: 70 }` 命中的是 xterm 的 `<div>`，终端一挂载就铺满整个
  视口并盖住顶栏（现象：进页面有顶栏，SSH 一连上顶栏就消失）。现在叫 `.terminal-view`。
- **终端布局用 grid**（`auto / minmax(0,1fr) / auto`）+ `overflow: hidden`：xterm 按像素设置自己的尺寸，
  flex 布局下容易把顶栏挤走或被覆盖。
- **终端路由锁滚动**：`body.is-terminal { overflow: hidden }`，否则 `term.focus()` / iOS 键盘弹出会把
  页面平移，顶栏被推出视口后不会自己回来。
- **渲染器**：优先加载 `@xterm/addon-webgl`（canvas/GPU 直接按格子绘制，不受 DOM 渲染器的 letter-spacing 补偿影响），
  失败或 context 丢失时自动 `dispose()` 回落到 DOM 渲染器，终端照常可用。
- **终端字体只能写单一 family**：xterm 用 canvas `measureText` 量格子、用 DOM 渲染文字。字体列表里排在前面
  但没安装的家族会让两者落到不同字体上，xterm 就给每个 span 补 `letter-spacing`（实测 -6.34px），
  字看起来全叠在一起。现在写死 `Consolas`，并在会话建立后用「DOM 渲染宽度 vs xterm 网格宽度」做一次
  漂移检查，偏差 >4% 时自动回退到 `monospace`。

## 已知限制 / 注意事项

- `/s/:id/terminal` 依赖 SPA 回退；如果换成自己的反向代理，记得把未知路径也回落到 `index.html`。

- `ssh2` 需要离线补丁才能在 workerd 上跑：`scripts/patch-ssh2.mjs` 会在 `npm install` 后
  - 移除加载 poly1305 WASM 的代码（workerd 禁止动态 `WebAssembly.instantiate`，且重试会耗尽内存）
  - 去掉 `cpu-features` 原生依赖与 ESM 下不存在的 `__dirname`
  - 把 `require('crypto')` 指向 `node:crypto`（unenv shim 缺 `diffieHellman`）
  - 因此**加密算法限定** `aes*-ctr` + `hmac-sha2-*-etm`，`kex` 走 `ecdh-sha2-nistp256`（curve25519 被 ssh2 的 `crypto.diffieHellman` 检测挡住）。现代 OpenSSH 都支持这些。
- 会话空闲 30 分钟自动断开；DO 关闭时会话即结束，不保留回放。
- 免费计划可跑（Durable Object 用 SQLite 后端），但 SSH 长连接会一直占着 DO。

## 目录

```
src/
  index.ts            Worker 路由（/api/*）
  auth.ts             Cloudflare Access JWT 验签
  store.ts            服务器清单（KV）+ 校验
  types.ts            共享类型
  lib/encoding.ts     base64url 等
  lib/secretbox.ts    AES-256-GCM 封装
  lib/ticket.ts       WebSocket 会话票据
  ssh/tcp.ts          cloudflare:sockets → Node Duplex
  ssh/session.ts      Durable Object：SSH 会话 / 测试连接
public/               前端（xterm.js、无构建）
scripts/patch-ssh2.mjs  ssh2 的 workerd 兼容补丁
cloudflare.config.ts   cf CLI 用的配置（cf deploy / cf dev）
wrangler.jsonc         wrangler 用的配置（wrangler dev / wrangler deploy）
```
