# GSA 快速校验（极简模型）

一线程 = 一条 SOCKS5 + 一台设备 + 一条长连接，账号按线程预切分，IP 走池。
单条 CPU 约 6.6 ms，4 核上限约 600 条/秒。

## 快速开始

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# 编辑 secrets.json 填入代理接口
.venv/bin/python simple.py --accounts data/accounts.txt --threads 1000 --limit 0
```

详细部署（Linux 4 核 4G）见 **DEPLOY.md**。

## 三个入口

| 脚本 | 用途 |
|---|---|
| `simple.py` | 单进程，1 核，约 30-33 万/小时 |
| `run_mp.py` | 多进程，按 CPU 核数吃满，约 60 万/小时 |
| `web.py` | 图形控制台，上传账号 + 设线程 + 实时看板 |

## 关键参数

| 参数 | 说明 |
|---|---|
| `--threads` | 每进程线程数，建议 500-1000 |
| `--per-ip` | 一条 IP 跑几条账号，默认 6 |
| `--limit` | 跑多少条，0 = 全部 |
| `--processes` | （run_mp）进程数 = CPU 核数 |
| `--verify-web` | GSA 判 `au=repair` 时用 web 协议细化 |

## 输出

- `data/live.json` — 实时状态（进度/速度/CPU/状态分布）
- `data/simple-run.jsonl` 或 `data/mp-p*.jsonl` — 逐条结果
- 状态口径与 `fastcheck` 原始项目一致（`result_bucket`）
