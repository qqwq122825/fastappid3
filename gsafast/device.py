"""设备池：槽位循环复用，默认永不丢弃。

和 cluster-lab 的 DeviceAuthLease 的区别：
  · 没有线性扫描、没有每线程 flock 轮询，交接走 Condition 队列；
  · 设备不按次数退役（use_limit=0），用完立刻回队列；
  · 只在 use_limit>0 且用满时才换一台新身份（重新 provisioning）。
"""
from __future__ import annotations

import threading
import time
from collections import Counter, deque


class DevicePool:
    def __init__(self, pool, *, capacity, use_limit=0, log=None):
        """pool: fastcheck.devices.DevicePool 实例
        capacity: 槽位总数（1..capacity）
        use_limit: 0=永不丢弃；>0=用满后换新身份
        """
        self.pool = pool
        self.capacity = max(1, int(capacity))
        self.use_limit = max(0, int(use_limit))
        self.log = log or (lambda *a, **k: None)
        self._cv = threading.Condition()
        self._free = deque()
        self._busy = set()
        self._uses = Counter()
        self._info = None
        self._info_at = 0.0
        self._info_ttl = 1800.0
        self.stats = {'acquire': 0, 'released': 0, 'rotated': 0, 'waited': 0,
                      'wait_seconds': 0.0, 'register_failed': 0}

    # ---------------------------------------------------------------- 预注册
    def info(self, timeout=20.0, *, proxy=None, refresh=False):
        now = time.monotonic()
        if self._info and not refresh and now - self._info_at < self._info_ttl:
            return dict(self._info)
        value = self.pool.info(timeout, proxy=proxy, provider_direct=True)
        self._info = dict(value)
        self._info_at = now
        return dict(self._info)

    def inspect(self, slot):
        return self.pool.inspect(slot)

    def provision(self, slots, *, threads=4, timeout=40.0, progress=None):
        """把一批槽位注册成 ready；已 ready 的直接跳过。"""
        ready, todo = [], []
        for slot in slots:
            state = self.pool.inspect(slot).get('state')
            if state == 'ready':
                ready.append(slot)
            else:
                todo.append(slot)
        if todo:
            from concurrent.futures import ThreadPoolExecutor
            info = self.info(timeout, refresh=True)

            def one(slot):
                try:
                    self.pool.fetch_headers(slot, info, timeout, registered=False,
                                            provider_direct=True)
                    return slot
                except Exception as exc:                            # noqa: BLE001
                    self.log('provision_failed', slot=slot,
                             error=type(exc).__name__)
                    return None

            with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
                done = 0
                for slot in executor.map(one, todo):
                    done += 1
                    if slot is not None:
                        ready.append(slot)
                    if progress and done % 20 == 0:
                        progress(done, len(todo), len(ready))
        with self._cv:
            for slot in sorted(set(ready)):
                if slot not in self._free and slot not in self._busy:
                    self._free.append(slot)
            self._cv.notify_all()
        self.log('devices_ready', total=len(set(ready)))
        return sorted(set(ready))

    # ---------------------------------------------------------------- 租还
    def acquire(self, wait=60.0):
        deadline = time.monotonic() + max(0.0, float(wait))
        with self._cv:
            while True:
                if self._free:
                    slot = self._free.popleft()
                    self._busy.add(slot)
                    self.stats['acquire'] += 1
                    return slot
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.stats['waited'] += 1
                    return None
                started = time.monotonic()
                self._cv.wait(min(0.25, remaining))
                self.stats['wait_seconds'] += time.monotonic() - started

    def release(self, slot, *, consume=True, proxy=None):
        """归还。consume=False 表示只借用（OTP 预取），不计入设备使用次数。"""
        if slot is None:
            return 'dropped'
        with self._cv:
            self._busy.discard(slot)
            if consume:
                self._uses[slot] += 1
            self.stats['released'] += 1
            self._cv.notify()
        if not consume:
            with self._cv:
                if slot not in self._free and slot not in self._busy:
                    self._free.append(slot)
                    self._cv.notify()
            return 'returned'
        if self.use_limit and self._uses[slot] >= self.use_limit:
            # 换新身份但仍复用这个槽位号
            try:
                info = self.info(40.0)
                self.pool.fetch_headers(slot, info, 40.0, registered=False,
                                        provider_direct=True)
                self.stats['rotated'] += 1
                self.log('device_rotated', slot=slot, uses=self._uses[slot])
            except Exception as exc:                                # noqa: BLE001
                self.stats['register_failed'] += 1
                self.log('device_rotate_failed', slot=slot,
                         error=type(exc).__name__)
            with self._cv:
                self._uses[slot] = 0
        with self._cv:
            if slot not in self._free and slot not in self._busy:
                self._free.append(slot)
                self._cv.notify()
        return 'pooled'

    def snapshot(self):
        with self._cv:
            return {'capacity': self.capacity, 'free': len(self._free),
                    'busy': len(self._busy), 'use_limit': self.use_limit,
                    'max_uses': max(self._uses.values()) if self._uses else 0,
                    **self.stats}
