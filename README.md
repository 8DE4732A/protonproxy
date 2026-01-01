# ProtonVPN Python Proxy

使用 ProtonVPN 浏览器扩展的代理功能，提供本地 HTTP 代理服务，使任何应用程序都可以通过 ProtonVPN 路由流量。

## 安装

```bash
cd /path/to/protonproxy
uv sync
```

## 使用方法

### 1. 登录

```bash
uv run protonproxy login
```

这将打开浏览器进行 Proton 账户登录。登录成功后，session 将保存在 `~/.protonproxy/session.json`。

### 2. 查看可用服务器

```bash
# 查看可用国家
uv run protonproxy countries

# 查看所有服务器
uv run protonproxy servers

# 只看特定国家的服务器
uv run protonproxy servers -c US
```

### 3. 启动代理

```bash
# 自动选择最佳免费服务器
uv run protonproxy connect

# 选择特定国家
uv run protonproxy connect -c JP

# 选择特定服务器
uv run protonproxy connect -s "JP#9"

# 自定义端口
uv run protonproxy connect --port 1080
```

### 4. 链式代理（可选）

如果需要通过另一个代理访问 ProtonVPN（例如在受限网络环境下），可以指定上游代理：

```bash
# 通过 SOCKS5 代理
uv run protonproxy connect --upstream socks5://127.0.0.1:1080

# 通过 HTTP 代理
uv run protonproxy connect --upstream http://proxy.example.com:8080

# 带认证的代理
uv run protonproxy connect --upstream socks5://user:pass@127.0.0.1:1080
```

支持的代理类型：
- `socks5://` - SOCKS5 代理
- `socks4://` - SOCKS4 代理
- `http://` - HTTP 代理

### 5. 配置应用程序

启动代理后，配置你的应用程序使用 HTTP 代理：

- **代理地址**: `127.0.0.1:8080`
- **代理类型**: HTTP

示例：
```bash
# curl
curl --proxy http://127.0.0.1:8080 https://api.ipify.org

# 环境变量
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

### 6. 退出登录

```bash
uv run protonproxy logout
```

## 命令参考

| 命令 | 说明 |
|------|------|
| `login` | 通过浏览器登录 |
| `logout` | 退出登录 |
| `status` | 检查登录状态 |
| `servers` | 列出可用服务器 |
| `countries` | 列出可用国家 |
| `connect` | 启动代理连接 |

### connect 选项

| 选项 | 说明 |
|------|------|
| `-c, --country` | 连接到指定国家的最佳服务器 |
| `-s, --server` | 连接到指定服务器 (如 JP#9) |
| `-a, --all` | 显示/使用所有层级服务器（不仅限免费） |
| `--host` | 本地代理监听地址 (默认 127.0.0.1) |
| `--port` | 本地代理端口 (默认 8080) |
| `-u, --upstream` | 上游代理 URL (如 socks5://127.0.0.1:1080) |

## 注意事项

⚠️ **使用风险**: 在浏览器扩展之外使用此代理可能违反 ProtonVPN 服务条款。请自行承担风险。

⚠️ **免费账户限制**: 免费账户只能访问 Tier 0 服务器。

