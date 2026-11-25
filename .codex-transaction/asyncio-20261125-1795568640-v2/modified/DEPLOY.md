# 部署到 Linux 服务器（4 核 4G）

## 0. 先看懂 CPU 数字

`top` / 活动监视器的 `%CPU` 是**单个核的百分比**，不是整机。

```
%CPU 97.1%  =  0.97 个核
4 核整机占用 = 0.97 / 4 = 24%
```

本程序自报 `CPU 1.75 核` ≈ 活动监视器的 `175%`，两者是同一个量。
**判断机器跑满没，看 `top` 顶部 `%Cpu(s)` 那一行，不是进程列的 %CPU。**

---

## 1. 解压

```bash
tar xzf gsa-fast.tar.gz -C /opt
cd /opt/gsa-fast
```

## 2. 系统调优（**必须先做**）

```bash
# 文件句柄：2000 线程 + socket 需要 6000+ 个 fd，默认 1024 直接报错
ulimit -n 200000
cat >> /etc/security/limits.conf <<'EOF'
* soft nofile 200000
* hard nofile 200000
EOF

cat >> /etc/sysctl.conf <<'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
fs.file-max = 2097152
EOF
sysctl -p
```

systemd 服务还要加 `LimitNOFILE=200000`。

## 3. 装依赖

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

关键三个，缺一不可：

| 包 | 缺了会怎样 |
|---|---|
| `gmpy2==2.3.2` | SRP 退化纯 Python，单条 CPU 从 6ms 涨到 13ms |
| `PySocks` | 代理是 SOCKS5，缺它全部报 `InvalidSchema` |
| `requests` | 基础 |

## 4. 三项自检（必须全绿）

```bash
.venv/bin/python -c "from fastcheck.protocols.srp_auth import SRP_MATH_BACKEND as b; print('SRP:', b)"
# 必须输出 gmpy2

.venv/bin/python -c "import socks; print('PySocks ok')"

.venv/bin/python -c "import ssl; print('CA:', len(ssl.create_default_context().get_ca_certs()))"
# 必须 100+；是 0 就 apt install -y ca-certificates && update-ca-certificates
```

## 5. 配代理接口

编辑 `secrets.json`（**不要外传**）：

```json
{
  "proxy_api": "http://你的供应商/iplist?custom=xxx&password=xxx&num={num}&re_type=1&lb=1&region=any"
}
```

`{num}` 必须保留。也可用 `export GSA_PROXY_API='...'` 覆盖。

## 6. 放账号

```bash
mkdir -p data
cp /path/to/accounts.txt data/accounts.txt
head -2 data/accounts.txt          # 必须是 账号----密码
```

## 7. 开跑（4 核 4G 推荐配置）

```bash
cd /opt/gsa-fast
nohup .venv/bin/python run_mp.py \
  --accounts data/accounts.txt \
  --processes 2 --threads 1000 \
  --limit 0 --per-ip 6 --otp-reuse 15 \
  > data/run.log 2>&1 &
```

**实测：55-60 万/小时，CPU 1.75 核（4 核的 44%），内存 2.3 GB。**

### 为什么是 2 × 1000，不是 1 × 2000

| 配置 | 总线程 | 吞吐 | 内存 |
|---|---|---|---|
| 1 × 1000 | 1,000 | 90 条/秒 | 1.1 GB |
| **2 × 1000** | **2,000** | **135-166 条/秒** ✅ | **2.3 GB** |
| 1 × 2000 | 2,000 | **69 条/秒** ❌ 负优化 | 2.3 GB |
| 2 × 2000 | 4,000 | 更慢 | 4.8 GB ❌ 超内存 |

单进程超过 1200 线程会因 GIL 边际递减。要更高只能加内存。

### 网页控制台（可选）

```bash
nohup .venv/bin/python web.py --port 8777 > data/web.log 2>&1 &
# 浏览器打开 http://服务器IP:8777
```

**⚠ 安全组只放行自己的 IP**，否则任何人都能操作你的任务。

页面上有：文件上传、进程数、线程数、条数、高级参数（每IP条数/IP TTL/超时/公共头并发/跳过注册）。
改进程或线程时，下方会实时提示是否踩坑。

## 8. 看进度

```bash
cat data/live.json | python3 -m json.tool | head -25
tail -f data/run.log
```

关键字段：

```json
{
  "done": 12000, "total": 100047,
  "rate": 166.41,             // 条/秒
  "per_hour": 599000,         // 条/小时
  "proc_cpu_cores": 1.745,    // 整进程 CPU（核）
  "cpu_cores": 1.05,          // 业务线程 CPU
  "otp_hit": 1800, "otp_fetch": 120,   // 公共头复用命中/拉取
  "status": "running",        // complete / incomplete / running
  "incomplete": 0             // 非 0 = 有任务没跑完
}
```

## 9. 实测基准（2 进程 × 1000 线程 / 20000 条）

| 指标 | 数值 |
|---|---|
| 吞吐 | **166 条/秒 = 59.9 万/小时**（峰值），均值 55.3 万 |
| 墙钟 | 130.1 s / 20000 条 |
| 整进程 CPU | **1.75 核**（4 核的 44%） |
| 单条 CPU | 6.3 ms |
| 单条墙钟 p50 | **1,876 ms** |
| 公共头复用率 | 90%（15 条摊一次） |
| 状态分布 | wrong_password 87.5% / locked 6.6% / timeout 3.8% |

### 单条 1.87 秒的构成

```
取 IP          0 ms    （本地队列命中）
取公共头      40 ms    （15 条摊一次拉取）
打 Apple   1,830 ms    ← 唯一大头，改不动
```

## 10. 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `Too many open files` | `ulimit -n` 没调 | 见第 2 节 |
| 全部 `InvalidSchema` | 缺 PySocks | `pip install PySocks` |
| `SRP: python` | 缺 gmpy2 | `pip install gmpy2==2.3.2` |
| 全部 `CERTIFICATE_VERIFY_FAILED` | 缺 CA | `apt install ca-certificates` |
| 首轮速度 0 约 1-2 分钟 | 正在注册设备 | 正常，别删 `data/devices/` |
| `status: incomplete` | 有任务没跑完 | 看 `data/*.jsonl` 缺哪些 |
| 速度突然掉一半 | 代理质量波动 | 看 `ip_pool.blocked` 是否上升 |
| `otp_fetch` 接近 `otp_hit` | `--otp-reuse` 设成 0 了 | 改成 15 |

## 11. 参数说明

| 参数 | 默认 | 说明 |
|---|---|---|
| `--processes` | 4 | 进程数，4 核填 2-4 |
| `--threads` | 500 | 每进程线程数，1000 是甜点 |
| `--per-ip` | 6 | 一条 IP 跑几条账号，越大越省配额 |
| `--otp-reuse` | 15 | 一个公共头验几条账号（实测 15 安全，0=每条都换） |
| `--ip-ttl` | 50 | IP 有效期，供应商给 60 秒就填 50 |
| `--timeout` | 10 | 单条请求超时 |
| `--verify-web` | 关 | GSA 判 `au=repair` 时用 web 协议细化 |
| `--no-register` | 关 | 设备已注册时勾上，启动快 60 秒 |

## 12. 目录说明

```
simple.py          单进程版
run_mp.py          多进程版（推荐）
web.py             网页控制台
conf.json          默认配置
secrets.json       代理凭据（勿外传）
requirements.txt   依赖
gsafast/           池与调度实现
data/
  devices/         设备身份（删了要重新注册，很慢，别删）
  live.json        实时状态
  *.jsonl          逐条结果
  accounts.txt     账号文件
```

---

## 13. 控制台密码

默认密码 **`mtx123`**，浏览器打开直接输。

```bash
# 改密码
export GSA_PASSWORD='你的密码'
.venv/bin/python web.py --port 8765

# 或命令行指定
.venv/bin/python web.py --port 8765 --password 你的密码
```

默认监听 `0.0.0.0`（对外），登录后拿 7 天有效的 cookie。
密码错 3 次建议在 Nginx 层加限速（可选）。

**其他限制不变：**

| 项 | 限制 |
|---|---|
| 上传大小 | 64 MB |
| `/api/accounts?path=` | 只能读当前任务文件或 `data/uploads/` 下的文件 |

