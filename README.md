# 企业微信通知转发服务 (wechatpush-go)

类似 Server 酱的轻量级企业微信消息推送与回调服务，基于 **Go 1.27.3** 构建。通过企业微信自建应用将告警、监控、CI/CD 通知精准推送到指定成员/部门/标签，并支持企业微信双向回调验证与消息处理。

本项目是 `qywx-notifier-plus` (`v2.0.0`) 的 **Go 1:1 重构版**，完整保留多应用管理、三层发送开关、乐观锁并发控制 (`If-Match`)、双模式通知鉴权及全套 Web 管理界面，同时编译为无 CGO 依赖 (`CGO_ENABLED=0`) 的独立单文件二进制。

---

## 核心特性

- **单文件零依赖部署 (`embed.FS` + 纯 Go SQLite)**：前端 `public/` 静态资源直接内嵌至可执行文件，数据库采用纯 Go 驱动 `modernc.org/sqlite`，无需安装 Node.js、C 编译器或外部数据库。
- **多应用分组管理**：同一企业或不同企业可接入多个不同 `AgentID` 的自建应用，支持 4 步新建向导（回调配置 → 凭证校验 → 接收人选择 → 完成确认）与草稿自动恢复。
- **三层发送开关控制**：
  - **应用总开关 (`app_enabled`)**：一键暂停/恢复该应用下所有默认 Code 与规则 API 的通知下发。
  - **规则独立开关 (`rule.enabled`)**：每个转发规则拥有独立推送码与接收人列表，可单独启停。
  - **应用级 Code 直发开关 (`code_send_enabled`)**：可关闭应用默认推送码直发，强制外部调用方仅通过受控的规则推送码发送。
- **企业级安全防护**：
  - **启动安全基线强校验**：拒绝空密码、弱口令、示例占位密钥与非授信生产企微 API 地址。
  - **AES-256-GCM 认证加密**：数据库中的 `corp_id`、`corp_secret`、`callback_token`、`encoding_aes_key` 全量加密落盘（自动兼容旧版 CBC 密文平滑迁移）。
  - **双模式通知鉴权**：支持 `X-Notify-Key` 明文密钥比对（恒定时间防时序攻击）与 `HMAC-SHA256` 签名校验（`X-Notify-Timestamp` / `X-Notify-Nonce` / `X-Notify-Signature` + 分区防重放缓存）。
  - **多设备会话管理与防爆破**：管理后台采用 `HttpOnly + SameSite=Lax` Cookie 会话，支持查看活跃设备会话、一键吊销会话，并内置按用户名+IP 的登录限流。
- **终端与编码友好**：自动检测并转码 Windows PowerShell / CMD `curl` 发送的 GBK / GB18030 中文请求体，且保留原始字节流验签；支持 30 秒相同消息幂等去重缓存与 `force: true` 强制穿透。

---

## 目录结构

```text
wechatpush-go/
├── cmd/server/main.go            # 服务入口、启动自检与优雅停机控制
├── embed.go                      # go:embed 内嵌 public/ 前端静态资源
├── internal/
│   ├── auth/                     # 恒定时间凭据比对、Session 管理与 Cookie 构建
│   ├── bodyparser/               # UTF-8 校验与 GBK/GB18030 自动转码解析器
│   ├── config/                   # 环境变量加载与启动安全基线校验
│   ├── crypto/                   # AES-256-GCM 加解密与旧版 CBC 自动迁移
│   ├── database/                 # SQLite 串行事务队列、触发器与命名空间审计
│   ├── notifyauth/               # 通知通道 API Key / HMAC-SHA256 验签与分区 LRU 防重放
│   ├── notifycode/               # 推送码规范化、格式校验与生成
│   ├── ratelimit/                # 滑动窗口速率限制器与登录失败防爆破限制器
│   ├── server/                   # HTTP 路由、安全响应头、TRUST_PROXY 解析与中间件
│   ├── service/                  # 核心通知编排、多应用生命周期、配额预扣与回滚
│   ├── wechat/                   # 企业微信 API 客户端与 AccessToken 自动刷新重试
│   └── wxcrypt/                  # 企业微信回调 WXBizMsgCrypt 加解密与 XML 解析
├── public/                       # Web 管理端前端静态资源
├── tools/e2e/                    # 端到端全场景模拟回归测试工具
├── Dockerfile                    # 多阶段最小化容器构建文件
├── docker-compose.yml            # Docker Compose 编排文件
└── env.template                  # 环境变量配置模板
```

---

## 部署教程

提供三种部署方式：**Docker Compose 部署（推荐）**、**1Panel 面板可视化部署**、**独立二进制部署（Linux Systemd / Windows）**。

### 方式一：Docker Compose 部署（推荐生产环境）

镜像地址：`ghcr.io/mmlxm2025/wechatpush-go:latest`

#### 第 1 步：创建目录并准备配置文件

**方式 A：仅下载编排文件直接拉取官方镜像（无需下载源码）**

```bash
mkdir -p /opt/wechatpush-go && cd /opt/wechatpush-go

curl -fsSL https://raw.githubusercontent.com/mmlxm2025/wechatpush-go/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/mmlxm2025/wechatpush-go/main/env.template -o .env
```

**方式 B：克隆源码本地构建启动**

```bash
git clone https://github.com/mmlxm2025/wechatpush-go.git /opt/wechatpush-go
cd /opt/wechatpush-go
cp env.template .env
```

#### 第 2 步：生成安全密钥并修改 `.env`

在服务器终端生成高强度随机密钥与管理员密码：

```bash
# 生成 64 位十六进制加密密钥（解码后恰好 32 字节，用于 ENCRYPTION_KEY）
openssl rand -hex 32

# 生成高强度随机管理员密码（用于 ADMIN_PASSWORD）
openssl rand -base64 24
```

编辑 `.env` 文件（`nano .env` 或 `vi .env`），填入刚生成的值：

```ini
# 监听地址与端口：
# - 若通过同机 Nginx / 1Panel / Caddy 反向代理访问，建议设为 127.0.0.1
# - 若在内网或直接通过 IP:端口 访问，保持 0.0.0.0
HOST_BIND=127.0.0.1
HOST_PORT=12121

# 【必改】加密数据库中企业微信密钥的主密钥（支持 32 字符明文 / 64 位 hex / 44 位 base64）
# ⚠️ 首次产生业务数据后请勿更换，否则已加密的企微凭证将无法解密！
ENCRYPTION_KEY=粘贴上面生成的64位hex密钥

# 【必改】管理后台登录账号与密码（密码至少 8 位，不可使用默认占位值）
ADMIN_USERNAME=admin
ADMIN_PASSWORD=粘贴上面生成的强密码

# 反向代理信任策略：
# - 直接暴露端口访问时必须保持 false
# - 同机反向代理（HOST_BIND=127.0.0.1）设为 loopback
# - 容器网络反向代理可设为反代容器 IP / CIDR（如 172.16.0.0/12）或跳数 1
TRUST_PROXY=loopback

# 企业微信官方 API 地址（默认即可）
WECHAT_API_BASE=https://qyapi.weixin.qq.com
```

保护 `.env` 文件权限：

```bash
chmod 600 .env
```

#### 第 3 步：启动服务并验证

```bash
# 直接拉取镜像启动（方式 A）：
docker compose pull && docker compose up -d

# 或本地源码构建启动（方式 B）：
docker compose up -d --build

# 查看运行与健康检查状态（STATUS 应显示为 Up ... (healthy)）
docker compose ps

# 查看启动日志
docker compose logs --tail=50

# 本机探活验证
curl -i http://127.0.0.1:12121/health/ready
```

---

### 方式二：1Panel 面板可视化部署

1. **准备目录与 `.env`**：
   - 打开 1Panel 左侧「文件」，进入 `/opt` 目录并新建文件夹 `wechatpush-go`。
   - 将仓库中的 `docker-compose.yml` 和 `env.template` 上传至 `/opt/wechatpush-go`，并将 `env.template` 重命名为 `.env`（若看不到 `.env`，请开启右上角「显示隐藏文件」）。
   - 双击编辑 `.env`，设置：
     - `HOST_BIND=127.0.0.1`
     - `HOST_PORT=12121`
     - `ENCRYPTION_KEY=`（填入 32 位随机字符或 64 位 hex）
     - `ADMIN_PASSWORD=`（填入至少 8 位强密码）
     - `TRUST_PROXY=loopback`
2. **创建容器编排**：
   - 打开 1Panel「容器」→「编排」→「创建编排」。
   - 名称填写 `wechatpush-go`，路径选择 `/opt/wechatpush-go`，确认后点击启动。
3. **配置 HTTPS 反向代理**：
   - 打开 1Panel「网站」→「创建网站」→「反向代理」。
   - 主域名填写你的通知域名（如 `push.example.com`），代理地址填写 `http://127.0.0.1:12121`。
   - 为该网站启用 SSL（HTTPS）证书，浏览器访问 `https://push.example.com` 即可登录管理后台。

---

### 方式三：独立二进制部署（Linux / Windows / macOS）

本项目无任何 CGO 依赖，可直接编译为单个可执行文件运行（前端静态资源已内置于二进制中，无需额外部署 `public/` 目录）。

#### 1. 编译二进制文件

```bash
# 当前系统原生编译
go build -trimpath -ldflags="-s -w" -o wechatpush ./cmd/server

# Linux amd64 交叉编译（在 Windows PowerShell 下执行）
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="amd64"; go build -trimpath -ldflags="-s -w" -o wechatpush ./cmd/server

# Linux arm64 交叉编译
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="arm64"; go build -trimpath -ldflags="-s -w" -o wechatpush-arm64 ./cmd/server

# Windows amd64 编译
$env:CGO_ENABLED="0"; $env:GOOS="windows"; $env:GOARCH="amd64"; go build -trimpath -ldflags="-s -w" -o wechatpush.exe ./cmd/server
```

#### 2. Linux Systemd 守护进程部署

将编译好的二进制文件 `wechatpush` 与 `env.template` 上传到 `/opt/wechatpush-go/`：

```bash
sudo mkdir -p /opt/wechatpush-go/database
sudo cp wechatpush /opt/wechatpush-go/
sudo cp env.template /opt/wechatpush-go/.env
sudo chmod +x /opt/wechatpush-go/wechatpush
sudo chmod 600 /opt/wechatpush-go/.env
# 编辑 /opt/wechatpush-go/.env 修改 ENCRYPTION_KEY、ADMIN_PASSWORD，并将 NODE_ENV 设为 production
```

创建 Systemd 服务文件 `/etc/systemd/system/wechatpush.service`：

```ini
[Unit]
Description=WeChat Work Notification Service (Go)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/wechatpush-go
EnvironmentFile=/opt/wechatpush-go/.env
ExecStart=/opt/wechatpush-go/wechatpush
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

启动并设置开机自启：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wechatpush
sudo systemctl status wechatpush
```

#### 3. Windows 本地运行

```powershell
# 复制配置文件并修改其中的 ENCRYPTION_KEY 与 ADMIN_PASSWORD
Copy-Item env.template .env
notepad .env

# 启动服务（自动读取同目录下的 .env）
.\wechatpush.exe
```

启动后浏览器访问 `http://localhost:12121` 即可进入管理后台。

---

## Nginx 反向代理配置示例

生产环境强烈建议前置 HTTPS 反向代理，并在 `.env` 中配置 `TRUST_PROXY=loopback`（同机反代）：

```nginx
server {
    listen 443 ssl http2;
    server_name push.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:12121;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 日常运维：更新、备份与恢复

### 1. 更新版本（Docker Compose）

```bash
cd /opt/wechatpush-go
docker compose pull
docker compose up -d
docker image prune -f
```

### 2. 数据库备份与恢复

所有应用配置与转发规则均存储在 `./database/notifier.db` 中（密文由 `.env` 中的 `ENCRYPTION_KEY` 保护，**请务必将 `.env` 与 `notifier.db` 一并妥善备份**）：

```bash
# 备份数据库与 .env
cd /opt/wechatpush-go
tar czf wechatpush-backup-$(date +%F).tar.gz .env database/

# 恢复备份（先停止容器，解压后再启动）
docker compose down
tar xzf wechatpush-backup-YYYY-MM-DD.tar.gz
docker compose up -d
```

---

## 环境变量说明

| 变量 | 默认值 | 必填 | 说明 |
|------|--------|------|------|
| `ENCRYPTION_KEY` | 无 | **必改** | 数据库敏感字段加密密钥，支持 32 字符原始串、64 位 hex 或 44 位 base64。**产生数据后不可更改** |
| `ADMIN_USERNAME` | `admin` | 建议修改 | 管理后台登录用户名 |
| `ADMIN_PASSWORD` | 无 | **必改** | 管理后台登录密码，长度至少 8 位且不能为示例占位值 |
| `PORT` | `12121` | 否 | 服务监听端口 |
| `HOST_BIND` | `0.0.0.0` | 否 | Docker Compose 宿主机绑定地址（反代场景建议 `127.0.0.1`） |
| `HOST_PORT` | `12121` | 否 | Docker Compose 宿主机映射端口 |
| `DB_PATH` | `./database/notifier.db` | 否 | SQLite 数据库文件路径 |
| `NODE_ENV` | `production` | 否 | 运行环境模式（生产环境默认 `production`） |
| `TRUST_PROXY` | `false` | 否 | 反向代理信任设置：`false`、`true`、`loopback`、跳数（如 `1`）或 IP/CIDR 列表 |
| `WECHAT_API_BASE` | `https://qyapi.weixin.qq.com` | 否 | 企业微信 API 地址（生产环境强制校验 HTTPS 官方域名，自定义代理需同时设 `WECHAT_ALLOW_CUSTOM_API_BASE=1`） |
| `SEND_DEDUP_TTL_MS` | `30000` | 否 | 相同消息幂等去重时间窗（毫秒），请求体传 `"force": true` 可跳过 |
| `WECHAT_MAX_REQUEST_BYTES` | `5242880` | 否 | 发往企业微信的请求体上限（字节，默认 5MB） |
| `WECHAT_MAX_RESPONSE_BYTES` | `5242880` | 否 | 读取企业微信响应体上限（字节，默认 5MB） |
| `SKIP_STARTUP_VALIDATION` | 未设置 | 否 | 设为 `1` 时跳过启动安全校验（仅非 `production` 环境生效） |

---

## 通知发送接口快速调用示例

登录管理后台完成应用或转发规则创建后，即可通过 `POST /api/notify/:code` 发送通知（完整文档请访问服务内的 `/api-docs.html`）：

### 1. 发送文本 / Markdown 消息

```bash
curl -X POST "https://push.example.com/api/notify/你的推送码" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "服务器告警",
    "content": "节点 node-01 CPU 使用率超过 90%",
    "msgType": "text"
  }'
```

### 2. 开启通知密钥后的鉴权调用

若在应用「安全设置」中启用了通知密钥（`X-Notify-Key`）：

```bash
curl -X POST "https://push.example.com/api/notify/你的推送码" \
  -H "Content-Type: application/json" \
  -H "X-Notify-Key: 你的通知密钥" \
  -d '{
    "title": "发布完成",
    "content": "**v2.0.0** 已成功部署上线",
    "msgType": "markdown"
  }'
```

---

## 常见问题排查 (FAQ)

1. **启动报错：`ENCRYPTION_KEY 必须解码为 32 字节` 或 `使用了不安全的示例占位值`**
   - 请确认 `.env` 已创建，且 `ENCRYPTION_KEY` 已替换为 `openssl rand -hex 32` 生成的 64 位十六进制字符串（或正好 32 个 ASCII 字符）。
2. **启动报错：`ADMIN_PASSWORD 长度不能少于 8 位` 或 `使用了不安全的示例占位值`**
   - 请修改 `.env` 中的 `ADMIN_PASSWORD`，设置至少 8 位的高强度密码。
3. **配置 HTTPS 反向代理后，登录 Cookie 异常或限流 IP 显示为 `127.0.0.1`**
   - 请检查反向代理是否传递了 `X-Forwarded-For` 和 `X-Forwarded-Proto` 请求头，并在 `.env` 中设置 `TRUST_PROXY=loopback`（若反代在另一容器内，可设为 `TRUST_PROXY=1` 或对应容器网段 CIDR）。
4. **与原 Node.js 版数据库是否可直接混用？**
   - Go 重构版使用独立的 SQLite 表结构，不支持直接挂载旧 Node 版的 `notifier.db` 文件，请使用空目录初始化并在管理后台重新接入应用。

---

## 致谢

本项目源自 [wangwangit/qywx-push](https://github.com/wangwangit/qywx-push) 与 [mmlxm2025/qywx-notifier-plus](https://github.com/mmlxm2025/qywx-notifier-plus)，感谢原作者公开并维护原项目。
