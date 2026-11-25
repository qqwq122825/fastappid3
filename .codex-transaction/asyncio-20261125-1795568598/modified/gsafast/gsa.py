"""把 fastcheck 的 GSA 协议层挂进来，并暴露本项目需要的入口。"""
from __future__ import annotations

import sys
import threading


class Gsa:
    """薄封装：只做路径绑定和连接复用确认，不改协议实现。"""

    def __init__(self, fastcheck_root):
        if fastcheck_root not in sys.path:
            sys.path.insert(0, fastcheck_root)
        from fastcheck.protocols import gsa_status as gs
        from fastcheck.devices import DevicePool as FcDevicePool
        from fastcheck.protocols.srp_auth import SRP_MATH_BACKEND
        self.gs = gs
        self.FcDevicePool = FcDevicePool
        self.backend = SRP_MATH_BACKEND
        self._lock = threading.Lock()

    def device_pool(self, root, origin, capacity):
        return self.FcDevicePool(root, origin, max_devices=int(capacity))

    def check(self, email, password, proxy, timeout, retries, identity):
        return self.gs.check(email, password, proxy, timeout=timeout,
                             retries=retries, cancel=None, identity=identity)

    def session_of(self):
        """当前线程正在用的连接对象（用于确认复用是否生效）。"""
        return getattr(self.gs._TLS, 'sess', None)
