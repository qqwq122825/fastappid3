"""IP 池：启动时一次性灌满，按线程切开，线程取用走本地队列——不排队。

设计目标（按优先级）：
  1. **取 IP 不排队**：线程启动时本地队列里已经有 IP，acquire 只读自己的 deque，
     不碰任何共享锁；
  2. **池无上限**：能拉多少存多少，只去重，不设 target 上限；
  3. **TTL 50 秒**：每条带 expires_at，过期在取用时顺手剔除；
  4. **补货异步**：supplier 只在本地队列见底时才被唤醒，且只有它一个线程拉 API。

取用路径：
    acquire(tid)
      ├─ 本地 deque 有未过期的        → 直接返回，零锁
      ├─ 本地空 → 共享 SimpleQueue     → C 实现，一次 put/get ≈ 0.1µs
      └─ 都空 → 触发一次补货并短暂等待（只有这种情况才会等）
"""
from __future__ import annotations

import collections
import math
import queue
import threading
import time
import urllib.request


class IpPool:
    def __init__(self, api, *, threads=1000, ttl=50.0, per_ip=9,
                 batch=1000, refill_interval=2.0, log=None):
        self.api = api
        self.threads = max(1, int(threads))
        self.ttl = max(5.0, float(ttl))
        self.per_ip = max(1, int(per_ip))
        self.batch = max(1, int(batch))
        self.interval = max(0.5, float(refill_interval))
        self.log = log or (lambda *a, **k: None)

        # 每线程一个本地队列：只有一个线程读写，天然无锁
        self._local = {tid: collections.deque() for tid in range(self.threads)}
        self._shared = queue.SimpleQueue()      # C 实现，正常路径几乎不用
        self._seen = {}                         # proxy -> expires_at，仅用于去重/观测
        self._seen_lock = threading.Lock()
        self._refill_lock = threading.Lock()
        self.cpu_supplier = 0.0
        self.cpu_snapshot = 0.0
        self._cv = threading.Condition()
        self._stop = threading.Event()
        self._thread = None
        self.stats = {'warmed': 0, 'api_calls': 0, 'api_error': 0, 'fetched': 0,
                      'duplicate': 0, 'expired': 0, 'discarded': 0,
                      'local_hit': 0, 'shared_hit': 0, 'blocked': 0,
                      'blocked_seconds': 0.0, 'last_fetch_ms': 0.0}

    # ---------------------------------------------------------------- 拉取
    def _fetch(self, num):
        num = max(1, min(self.batch, int(num)))
        url = self.api.format(num=num)
        started = time.monotonic()
        try:
            with urllib.request.urlopen(url, timeout=25) as resp:
                body = resp.read().decode('utf-8', 'replace')
        except Exception as exc:                                    # noqa: BLE001
            self.stats['api_error'] += 1
            self.log('ip_api_error', error=type(exc).__name__)
            return []
        finally:
            self.stats['api_calls'] += 1
            self.stats['last_fetch_ms'] = round((time.monotonic() - started) * 1000, 1)
        values = []
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith('{') or ':' not in line:
                continue
            values.append(line if '://' in line else f'socks5h://{line}')
        self.stats['fetched'] += len(values)
        return values

    def _accept(self, values, now=None):
        """去重后带 expires_at 存进 _seen；返回 (proxy, expires_at) 列表。"""
        now = time.monotonic() if now is None else now
        expires = now + self.ttl
        fresh = []
        with self._seen_lock:
            for proxy in values:
                if proxy in self._seen and self._seen[proxy] > now:
                    self.stats['duplicate'] += 1
                    continue
                self._seen[proxy] = expires
                fresh.append((proxy, expires))
        return fresh

    # ---------------------------------------------------------------- 预热
    def warm(self, extra=0):
        """启动时灌满到 threads*(1+extra)；单次上限 batch，不够就循环拉。"""
        target = int(self.threads * (1 + max(0, extra)))
        fresh = []
        rounds = 0
        while len(fresh) < target and rounds < 8 and not self._stop.is_set():
            want = min(self.batch, target - len(fresh))
            values = self._fetch(want)
            rounds += 1
            if not values:
                break
            fresh.extend(self._accept(values))
        with self._cv:
            for index, item in enumerate(fresh):
                if index < self.threads and not self._local[index]:
                    self._local[index].append(item)          # 每线程先分 1 条
                else:
                    self._shared.put(item)                   # 其余进共享
            self.stats['warmed'] = len(fresh)
            self._cv.notify_all()
        self.log('ip_warmed', target=target, fresh=len(fresh), rounds=rounds)
        return len(fresh)

    # ---------------------------------------------------------------- 补货
    def start(self):
        self._thread = threading.Thread(target=self._supply, name='ip-supplier', daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
        if self._thread:
            self._thread.join(3)

    def _live_local(self):
        now = time.monotonic()
        return sum(1 for bucket in self._local.values() for _, exp in bucket if exp > now)

    def _prune_shared(self, limit=4000):
        """清掉共享队列里已过期的，避免队头堆满死货。"""
        now = time.monotonic()
        kept = []
        dropped = 0
        for _ in range(min(limit, self._shared.qsize())):
            try:
                item = self._shared.get_nowait()
            except queue.Empty:
                break
            if item[1] > now:
                kept.append(item)
            else:
                dropped += 1
        for item in kept:
            self._shared.put(item)
        self.stats['expired'] += dropped
        return dropped

    def _tracked_live(self, now):
        """在册未被取走、且未过期的条数（真正的库存）。"""
        with self._seen_lock:
            return sum(1 for exp in self._seen.values() if exp > now)

    def _supply(self):
        """唯一的 API 调用方。按"在册可用量"补货，不看本地队列空不空。"""
        sup0 = time.thread_time()
        try:
            self._supply_loop()
        finally:
            self.cpu_supplier = time.thread_time() - sup0

    def _supply_loop(self):
        while not self._stop.is_set():
            try:
                self._prune_shared()
                now = time.monotonic()
                live = self._tracked_live(now)
                # 同时在用的 IP 最多等于线程数；per_ip 是"一条用完再换"，
                # 不是并发量。按 threads*per_ip 算会多拉好几倍。
                floor = max(50, int(self.threads * 1.2))
                if live < floor:
                    need = max(100, self.threads - live)
                    values = self._fetch(min(need, self.batch))
                    fresh = self._accept(values)
                    with self._cv:
                        for item in fresh:
                            self._shared.put(item)
                        self._cv.notify_all()
                    if fresh:
                        self.log('ip_refilled', got=len(fresh), live=live)
            except Exception as exc:                                # noqa: BLE001
                self.log('ip_supply_error', error=type(exc).__name__)
            self._stop.wait(self.interval)

    # ---------------------------------------------------------------- 取还
    def acquire(self, tid, wait=30.0):
        """返回 (proxy, expires_at)；取用不排队，只有池真的空了才会短暂等待。"""
        bucket = self._local.get(tid)
        now = time.monotonic()
        if bucket:
            while bucket:
                proxy, exp = bucket.popleft()
                if exp > now:
                    self.stats['local_hit'] += 1
                    return proxy, exp
                self.stats['expired'] += 1
        while True:                                  # 逐条取，过期的直接丢，直到拿到能用的
            try:
                proxy, exp = self._shared.get_nowait()
            except queue.Empty:
                break
            if exp > time.monotonic():
                self.stats['shared_hit'] += 1
                with self._seen_lock:
                    self._seen.pop(proxy, None)
                return proxy, exp
            self.stats['expired'] += 1
        # 这里只等 supplier 补货，工作线程绝不自己发 API
        deadline = time.monotonic() + max(0.0, float(wait))
        while time.monotonic() < deadline and not self._stop.is_set():
            try:
                proxy, exp = self._shared.get(timeout=0.2)
            except queue.Empty:
                continue
            if exp > time.monotonic():
                self.stats['blocked'] += 1
                return proxy, exp
            self.stats['expired'] += 1
        self.stats['blocked'] += 1
        return None, 0.0

    def release(self, tid, proxy, expires_at, *, healthy=True):
        """还回去：未过期且健康，优先放回本地队列，其次共享。"""
        if not proxy:
            return 'dropped'
        now = time.monotonic()
        if not healthy or expires_at <= now:
            self.stats['discarded'] += 1
            with self._seen_lock:
                self._seen.pop(proxy, None)
            return 'discarded'
        bucket = self._local.get(tid)
        if bucket is not None:
            bucket.append((proxy, expires_at))
        else:
            self._shared.put((proxy, expires_at))
        with self._cv:
            self._cv.notify()
        return 'pooled'

    # ---------------------------------------------------------------- 观测
    def snapshot(self):
        now = time.monotonic()
        with self._seen_lock:
            tracked = sum(1 for exp in self._seen.values() if exp > now)
        local = self._live_local()
        return {'threads': self.threads, 'ttl': self.ttl, 'per_ip': self.per_ip,
                'tracked': tracked, 'local_live': local,
                'shared': self._shared.qsize(),
                'supplier_alive': bool(self._thread and self._thread.is_alive()),
                **self.stats}
