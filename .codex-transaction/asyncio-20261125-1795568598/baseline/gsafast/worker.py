"""业务线程：一台设备 + 一条出口 + 一条长连接，跑完配额再换。

关键点：fastcheck 的 `_session_for(proxy)` 是 thread-local 且按 proxy 命中，
所以只要本线程在一条出口上连续跑多条账号，SOCKS 与 TLS 握手就只发生一次。
"""
from __future__ import annotations

import json
import threading
import time


class Worker(threading.Thread):
    def __init__(self, tid, ctx):
        super().__init__(name=f'worker-{tid}', daemon=True)
        self.tid = tid
        self.ctx = ctx
        self.count = 0
        self.cpu_s = 0.0
        self.connections = 0

    def run(self):
        cfg, ctx = self.ctx.cfg, self.ctx
        while not ctx.stop.is_set():
            slot = ctx.devices.acquire(wait=30.0)
            if slot is None:
                break
            proxy = ctx.proxies.one(attempts=6)
            if proxy is None:
                ctx.devices.release(slot, consume=False)
                if ctx.stop.wait(1.5):
                    break
                continue

            first_session = None
            served = 0
            try:
                for _ in range(cfg.accounts_per_ip):
                    task = ctx.take_task()
                    if task is None:
                        break
                    identity = ctx.otp.get(slot, timeout=max(15.0, cfg.timeout * 2))
                    if identity is None:
                        ctx.devices.release(slot, consume=False)
                        slot = None
                        break
                    cpu0, started = time.process_time(), time.perf_counter()
                    try:
                        result = ctx.gsa.check(task['email'], task['password'], proxy,
                                               cfg.timeout, cfg.retries, identity)
                    except Exception as exc:                       # noqa: BLE001
                        result = {'status': 'error', 'kind': type(exc).__name__,
                                  'stage': 'worker'}
                    elapsed = (time.perf_counter() - started) * 1000
                    self.cpu_s += time.process_time() - cpu0
                    if first_session is None:
                        first_session = ctx.gsa.session_of()
                        self.connections += 1
                    elif ctx.gsa.session_of() is not first_session:
                        self.connections += 1          # 连接被换掉（不该发生）
                        first_session = ctx.gsa.session_of()
                    ctx.record(self.tid, slot, proxy, task, result, elapsed)
                    served += 1
            finally:
                if slot is not None:
                    ctx.devices.release(slot)
            self.count += served
            if served == 0 and ctx.tasks_empty():
                break


class Context:
    """一个进程内的共享状态。"""

    def __init__(self, *, cfg, gsa, devices, proxies, otp, tasks, sink, stop):
        self.cfg = cfg
        self.gsa = gsa
        self.devices = devices
        self.proxies = proxies
        self.otp = otp
        self.tasks = tasks
        self.sink = sink
        self.stop = stop
        self._lock = threading.Lock()
        self.done = 0
        self.by_status = {}
        self.samples = []
        self.started = time.monotonic()

    def take_task(self):
        with self._lock:
            if not self.tasks:
                return None
            return self.tasks.pop()

    def tasks_empty(self):
        with self._lock:
            return not self.tasks

    def record(self, tid, slot, proxy, task, result, elapsed):
        status = str(result.get('status') or 'error')
        row = {
            't': round(time.time(), 3), 'tid': tid, 'slot': int(slot),
            'proxy': proxy.split(':')[0] + ':***' if proxy else '',
            'row': task.get('row'), 'status': status,
            'kind': result.get('kind'), 'stage': result.get('stage'),
            'http': result.get('http'), 'ec': result.get('apple_ec'),
            'ms': round(elapsed, 1),
        }
        with self._lock:
            self.done += 1
            self.by_status[status] = self.by_status.get(status, 0) + 1
            if self.done % max(1, self.cfg.sample_every) == 0:
                self.samples.append(row)
        self.sink.write(json.dumps(row, ensure_ascii=False) + '\n')
        self.sink.flush()

    def snapshot(self):
        with self._lock:
            return {'done': self.done, 'by_status': dict(self.by_status),
                    'elapsed': round(time.monotonic() - self.started, 2)}
