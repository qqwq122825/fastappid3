# ID 校验

当前生产模型是 **Python 多进程 + 线程**：

```text
web.py  →  run_mp.py  →  simple.py  →  fastcheck/ + gsafast/ippool.py
  UI          进程分片          线程工作器          协议/设备/IP 池
```

## 快速启动

```bash
python3 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -r requirements.txt
export GSA_PASSWORD='请设置强密码'
.venv/bin/python web.py --host 0.0.0.0 --port 8600
```

打开 `http://服务器IP:8600`，在页面中保存代理接口、上传/选择账号文件后开始任务。

## 主要文件

| 路径 | 用途 |
|---|---|
| `web.py` | Web 控制台、配置持久化、任务启停、状态/结果展示 |
| `run_mp.py` | 多进程分片、状态汇总 |
| `simple.py` | 生产线程工作器 |
| `fastcheck/` | Apple GSA/IDMSA、SRP、TLS、设备协议 |
| `gsafast/ippool.py` | 进程内 IP 池 |
| `simple_async.py` | 异步实验实现，非当前 Web 生产入口 |
| `tests/` | 安全、并发、设备、状态回归测试 |
| `DEPLOY.md` | 环境依赖、首次部署、systemd、更新和回滚 |

## 数据与密钥

`data/`、`secrets.json`、`.env` 均为本地/服务器运行数据，已被 Git 忽略，不应提交。

```text
data/uploads/                 上传的账号文件
data/current-accounts.json    当前选中文件
data/devices-simple/          持久设备池
data/live.json                实时状态
data/mp-p*.jsonl              分进程结果
data/web.log                  Web 日志
secrets.json                  代理 API（页面保存）
```

## 测试

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile web.py run_mp.py simple.py
```

完整部署说明见 [DEPLOY.md](DEPLOY.md)。
