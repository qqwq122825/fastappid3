"""离线冒烟测试：不发任何网络请求，只验证池与线程模型的正确性。"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gsafast.device import DevicePool          # noqa: E402


class FakePool:
    """假 DevicePool：inspect 全 ready，fetch_headers 只等待不联网。"""

    def __init__(self, delay=0.0):
        self.delay = delay
        self.fetched = []
        self._lock = threading.Lock()

    def info(self, timeout=20, *, proxy=None, provider_direct=False, refresh=False):
        return {'X-Apple-I-MD-M': 'fake'}

    def inspect(self, slot):
        return {'slot': slot, 'state': 'ready', 'device_id': f'fake-{slot}'}

    def fetch_headers(self, slot, info, timeout, *, registered=True, proxy=None,
                      provider_direct=False):
        if self.delay:
            time.sleep(self.delay)
        with self._lock:
            self.fetched.append(slot)
        return {'X-Apple-I-MD': f'otp-{slot}-{len(self.fetched)}'}


def test_provision_and_lease():
    pool = FakePool()
    devices = DevicePool(pool, capacity=8, use_limit=0)
    ready = devices.provision([1, 2, 3, 4], threads=4)
    assert ready == [1, 2, 3, 4], ready
    seen = set()
    for _ in range(4):
        slot = devices.acquire(wait=1)
        assert slot in ready, slot
        seen.add(slot)
        devices.release(slot)
    assert seen == set(ready), seen
    snap = devices.snapshot()
    assert snap['free'] == 4, snap
    assert snap['use_limit'] == 0
    assert pool.fetched == []          # 全部已 ready，不该重复注册


def test_no_discard_when_limit_zero():
    pool = FakePool()
    devices = DevicePool(pool, capacity=2, use_limit=0)
    devices.provision([1, 2])
    for _ in range(50):
        slot = devices.acquire(wait=1)
        devices.release(slot)
    snap = devices.snapshot()
    assert snap['free'] == 2, snap           # 50 次之后仍然两台都在
    assert snap['rotated'] == 0, snap        # 从不换身份


def test_rotation_when_limit_set():
    pool = FakePool()
    devices = DevicePool(pool, capacity=1, use_limit=3)
    devices.provision([1])
    for _ in range(6):
        slot = devices.acquire(wait=1)
        devices.release(slot)
    snap = devices.snapshot()
    assert snap['rotated'] == 2, snap        # 3 次一换，6 次换两次


def test_borrow_does_not_consume():
    pool = FakePool()
    devices = DevicePool(pool, capacity=1, use_limit=1)
    devices.provision([1])
    slot = devices.acquire(wait=1)
    devices.release(slot, consume=False)     # OTP 预取借用法
    snap = devices.snapshot()
    assert snap['rotated'] == 0, snap
    assert snap['max_uses'] == 0, snap


def test_partition_is_disjoint():
    from gsafast.runner import partition
    items = list(range(1, 201))
    parts = [partition(items, 4, i) for i in range(4)]
    flat = [x for p in parts for x in p]
    assert sorted(flat) == items
    assert len(set(flat)) == len(flat)
    assert all(len(p) == 50 for p in parts)


def test_otp_pool_per_slot():
    from gsafast.otp import OtpPool
    pool = FakePool(delay=0.01)
    devices = DevicePool(pool, capacity=2, use_limit=0)
    devices.provision([1, 2])
    otp = OtpPool(devices, [1, 2], per_slot=1, prefetch_threads=2, timeout=1.0).start()
    time.sleep(0.5)
    seen = set()
    for _ in range(4):
        slot = 1 if _ % 2 == 0 else 2
        identity = otp.get(slot, timeout=2.0)
        assert identity is not None
        seen.add(identity['X-Apple-I-MD'].split('-')[1])
    otp.stop()
    assert seen <= {'1', '2'}, seen          # OTP 必须来自对应槽位


import unittest


class SmokeTest(unittest.TestCase):
    """让 `python -m unittest` / `pytest` 都能发现这些用例。"""
    def test_provision_and_lease(self): test_provision_and_lease()
    def test_no_discard_when_limit_zero(self): test_no_discard_when_limit_zero()
    def test_rotation_when_limit_set(self): test_rotation_when_limit_set()
    def test_borrow_does_not_consume(self): test_borrow_does_not_consume()
    def test_partition_is_disjoint(self): test_partition_is_disjoint()
    def test_otp_pool_per_slot(self): test_otp_pool_per_slot()


if __name__ == '__main__':
    import sys as _sys
    if '--unittest' in _sys.argv:
        unittest.main(argv=['x', '-v'])
    else:
        passed = 0
        for name, fn in sorted(globals().items()):
            if name.startswith('test_') and callable(fn):
                fn()
                print(f'  PASS {name}')
                passed += 1
        print(f'\n{passed} 项通过')
