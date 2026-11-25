"""OTP 预取池：把 /v3/get_headers 的 2.2 秒从业务线程关键路径上挪走。

硬约束：X-Apple-I-MD 是一次性 OTP，且必须与"哪台设备"对应。
所以这里按 slot 分组排队，业务线程只能取自己那台设备的 OTP。
"""
from __future__ import annotations

import threading
import time
from collections import deque


class OtpPool:
    def __init__(self, devices, slots, *, per_slot=3, prefetch_threads=8,
                 ttl=300.0, timeout=10.0, log=None):
        self.devices = devices
        self.slots = [int(s) for s in slots]
        self.per_slot = max(1, int(per_slot))
        self.ttl = max(30.0, float(ttl))
        self.timeout = float(timeout)
        self.log = log or (lambda *a, **k: None)
        self.prefetch_threads = max(1, int(prefetch_threads))
        self._cv = threading.Condition()
        self._q = {slot: deque() for slot in self.slots}
        self._cursor = 0
        self._stop = threading.Event()
        self._threads = []
        self.stats = {'produced': 0, 'failed': 0, 'consumed': 0, 'expired': 0,
                      'miss': 0}

    # ------------------------------------------------------------------ 生命周期
    def start(self):
        for index in range(self.prefetch_threads):
            thread = threading.Thread(target=self._run, name=f'otp-{index}', daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def stop(self):
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
        for thread in self._threads:
            thread.join(2)

    # ------------------------------------------------------------------ 预取
    def _next_slot(self):
        with self._cv:
            slot = self.slots[self._cursor % len(self.slots)]
            self._cursor += 1
            depth = len(self._q[slot])
        return slot, depth

    def _run(self):
        while not self._stop.is_set():
            slot, depth = self._next_slot()
            if depth >= self.per_slot:
                self._stop.wait(0.02)
                continue
            lease = None
            try:
                lease = self.devices.acquire(wait=5.0)
                if lease is None:
                    self._stop.wait(0.2)
                    continue
                info = self.devices.info(self.timeout)
                identity = self.devices.pool.fetch_headers(
                    lease, info, max(self.timeout, 40.0), registered=True,
                    provider_direct=True)
                with self._cv:
                    self._q[lease].append((identity, time.monotonic()))
                    self.stats['produced'] += 1
                    self._cv.notify()
            except Exception as exc:                                # noqa: BLE001
                self.stats['failed'] += 1
                self.log('otp_failed', slot=lease, error=type(exc).__name__)
                self._stop.wait(0.1)
            finally:
                if lease is not None:
                    self.devices.release(lease, consume=False)

    # ------------------------------------------------------------------ 取用
    def get(self, slot, timeout=30.0):
        """取该 slot 的 OTP；返回 identity 或 None。"""
        deadline = time.monotonic() + max(0.0, float(timeout))
        slot = int(slot)
        while not self._stop.is_set():
            with self._cv:
                bucket = self._q.get(slot)
                if bucket:
                    identity, at = bucket.popleft()
                    self._cv.notify()
                else:
                    identity = None
            if identity is not None:
                if time.monotonic() - at <= self.ttl:
                    self.stats['consumed'] += 1
                    return identity
                self.stats['expired'] += 1
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.stats['miss'] += 1
                return None
            with self._cv:
                self._cv.wait(min(0.2, remaining))
        return None

    def snapshot(self):
        with self._cv:
            depth = sum(len(b) for b in self._q.values())
            return {'slots': len(self.slots), 'queued': depth,
                    'per_slot': self.per_slot, 'threads': self.prefetch_threads,
                    **self.stats}
