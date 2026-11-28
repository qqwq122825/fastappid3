# ID 校验：环境与部署说明

> 当前生产入口：`web.py`；默认部署目录：`/www/wwwroot/fast3`；当前对外端口：`8600`。

## 1. 架构

```text
浏览器
  └─ web.py（配置/上传/任务/状态）
       ├─ 单进程：simple.py
       └─ 多进程：run_mp.py
            └─ N 个 simple.py 子进程
                 ├─ fastcheck/（GSA、IDMSA、SRP、TLS、设备）
                 └─ gsafast/ippool.py（每进程独立 IP 池）
```

Web 页面只填“总线程数”，程序按 8 个进程自动拆分；例如 `800 = 8 × 100`。

## 2. 环境要求

### 操作系统

- Linux x86_64（Ubuntu 22.04/24.04、Debian 12 或同类发行版）
- Python 3.11+，推荐 3.12/3.13
- Git 2.x
- 出站能访问代理供应商、Apple HTTPS 端点和 Anisette 提供端
- 入站仅放行 Web 端口（当前 `8600/tcp`），建议限制管理 IP

### 硬件建议

| 规模 | CPU | 内存 | 建议总并发 |
|---|---:|---:|---:|
| 测试 | 2 核 | 4 GB | 100–300 |
| 常规 | 8 核 | 8 GB | 800–1200 |
| 高并发 | 16 核+ | 16 GB+ | 逐步压测，不要一次拉满 |

SRP 加速使用 `gmpy2==2.3.2`。实际速度同时受 CPU、内存、出口 RTT、代理质量和远端限流影响。

## 3. 系统依赖

Ubuntu/Debian：

```bash
sudo apt update
sudo apt install -y git ca-certificates build-essential pkg-config \
  python3 python3-venv python3-dev libgmp-dev libmpfr-dev libmpc-dev
sudo update-ca-certificates
```

Python 包（来自 `requirements.txt`）：

| 包 | 用途 |
|---|---|
| `requests` | 同步 HTTP 和连接池 |
| `PySocks` | SOCKS5 代理 |
| `gmpy2==2.3.2` | SRP 大数运算加速 |
| `portalocker` | 设备持久化锁 |
| `websockets` + `python-socks` | 设备注册 WebSocket 代理 |
| `aiohttp` + `aiohttp-socks` | 异步实验模块/相关回归测试 |

## 4. 首次部署

```bash
sudo mkdir -p /www/wwwroot
cd /www/wwwroot
sudo git clone https://github.com/qqwq122825/fastappid3.git fast3
sudo chown -R "$USER":"$USER" /www/wwwroot/fast3
cd /www/wwwroot/fast3

python3 -m venv .venv
.venv/bin/pip install -U pip wheel
.venv/bin/pip install -r requirements.txt
mkdir -p data/uploads data/devices-simple
```

### 依赖自检

```bash
.venv/bin/python - <<'PY'
import requests, socks, gmpy2, ssl
from fastcheck.protocols.srp_auth import SRP_MATH_BACKEND
print('requests:', requests.__version__)
print('gmpy2:', gmpy2.version())
print('SRP:', SRP_MATH_BACKEND)
print('CA:', len(ssl.create_default_context().get_ca_certs()))
PY
```

`SRP` 应显示 `gmpy2`，`CA` 不应为 0。

## 5. 密钥与配置

### 控制台密码

```bash
export GSA_PASSWORD='换成强密码'
```

### 代理 API

推荐启动 Web 后在页面中填写并点击“保存接口”。程序把真实地址写入本机 `secrets.json`（权限 `0600`），页面只显示脱敏值。

也可以用环境变量覆盖：

```bash
export GSA_PROXY_API='http://供应商/iplist?...&num={num}&...'
```

`{num}` 必须保留。不要提交 `secrets.json`、`.env` 或账号文件。

## 6. 文件句柄与内核参数

2000 级别并发时，文件句柄不应使用默认 1024：

```bash
ulimit -n 200000
```

持久配置（按服务器情况调整）：

```bash
sudo tee /etc/sysctl.d/99-fast3.conf >/dev/null <<'SYSCTL'
fs.file-max = 2097152
net.core.somaxconn = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
SYSCTL
sudo sysctl --system
```

## 7. 手动启动

```bash
cd /www/wwwroot/fast3
export GSA_PASSWORD='换成强密码'
nohup .venv/bin/python web.py --host 0.0.0.0 --port 8600 \
  >> data/web.log 2>&1 &
```

检查：

```bash
pgrep -af 'web.py.*--port 8600'
curl -fsS http://127.0.0.1:8600/ | grep -o 'v[0-9.]*' | head -1
tail -n 100 data/web.log
```

## 8. systemd（推荐）

```bash
sudo tee /etc/fast3.env >/dev/null <<'ENV'
GSA_PASSWORD=换成强密码
ENV
sudo chmod 600 /etc/fast3.env

sudo tee /etc/systemd/system/fast3.service >/dev/null <<'UNIT'
[Unit]
Description=Fast3 ID verification console
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=www
Group=www
WorkingDirectory=/www/wwwroot/fast3
EnvironmentFile=/etc/fast3.env
ExecStart=/www/wwwroot/fast3/.venv/bin/python web.py --host 0.0.0.0 --port 8600
Restart=on-failure
RestartSec=3
LimitNOFILE=200000
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now fast3
sudo systemctl status fast3 --no-pager
```

如服务器运行用户不是 `www`，同步修改 `User`/`Group`，并确保它可读写项目和 `data/`。

## 9. 防火墙

```bash
# UFW 示例：只允许管理 IP
sudo ufw allow from <你的管理IP> to any port 8600 proto tcp
```

云服务器安全组也要做相同限制。不建议把未加 TLS 的 `8600` 对全网开放；生产建议放在 Nginx HTTPS 反向代理后面。

## 10. 更新、测试和回滚

### 更新

```bash
cd /www/wwwroot/fast3
git fetch origin
git pull --ff-only origin main
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
sudo systemctl restart fast3
```

### 回滚

```bash
cd /www/wwwroot/fast3
git log --oneline -10
git checkout <已验证的提交>
sudo systemctl restart fast3
```

故障处理完成后，再执行 `git switch main && git pull --ff-only` 恢复跟随主分支。

## 11. 运行数据与备份

更新代码不要删除：

```text
data/uploads/                 历史账号文件
data/current-accounts.json    当前文件选择
data/devices-simple/          持久设备池
data/*.jsonl                  任务结果
secrets.json                  代理 API
```

备份示例：

```bash
tar czf /root/fast3-data-$(date +%F-%H%M%S).tar.gz \
  -C /www/wwwroot/fast3 data secrets.json
```

## 12. 故障排查

```bash
cd /www/wwwroot/fast3
bash diag.sh 8600
cat data/live.json | .venv/bin/python -m json.tool | head -80
tail -f data/web.log
```

| 现象 | 检查 |
|---|---|
| `Too many open files` | `ulimit -n`、systemd `LimitNOFILE` |
| `SRP threading` / 速度明显下降 | 确认自检输出 `SRP: gmpy2` |
| `SOCKSHTTPSConnectionPool` | 代理 IP/端口连接失败；查看供应商成功率 |
| `public_header:ConnectionError` | Anisette 端点或当前出口不可达 |
| 本地快、服务器慢 | 对比 CPU、出口 RTT、代理质量、p50/p90 和错误分布 |
| 页面旧版 | 检查 `git rev-parse --short HEAD`，重启后强制刷新 |

## 13. 安全注意

- `secrets.json`、账号文件、结果和设备数据都不得提交 Git。
- 代理凭据如曾出现在 Git 历史中，仅从新提交删除不够，必须到供应商后台轮换密码/token。
- 端口限制来源 IP，设置强 `GSA_PASSWORD`，并优先通过 HTTPS 反向代理对外提供。
