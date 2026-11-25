"""每线程自取一条出口：不做共享池、不补货、不淘汰。

设计取舍（与 cluster-lab 的 NodeProxyPool 相反）：
  · 没有全局池，线程拿 IP 不经过任何共享锁；
  · 一次只取 num=1，拿到就用，用完换新；
  · 可选入池前 TCP 探活，把连不上目标的出口挡在外面；
  · 取不到就退避重试，绝不把"没 IP"当成账号结果。
"""
from __future__ import annotations

import random
import socket
import threading
import time
import urllib.request


class ProxySource:
    def __init__(self, api: str, *, precheck=True, precheck_timeout=4.0,
                 precheck_host="gsa.apple.com", precheck_port=443, log=None):
        self.api = api
        self.precheck = precheck
        self.precheck_timeout = float(precheck_timeout)
        self.precheck_host = precheck_host
        self.precheck_port = int(precheck_port)
        self.log = log or (lambda *a, **k: None)
        self.stats = {'fetched': 0, 'rejected': 0, 'empty': 0, 'api_error': 0}
        self._lock = threading.Lock()

    def fetch_batch(self, num=1):
        url = self.api.format(num=max(1, int(num)))
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                body = resp.read().decode("utf-8", "replace")
        except Exception as exc:                                    # noqa: BLE001
            with self._lock:
                self.stats['api_error'] += 1
            self.log('proxy_api_error', error=type(exc).__name__)
            return []
        values = [line.strip() for line in body.splitlines()
                  if line.strip() and ':' in line.strip() and not line.startswith('{')]
        with self._lock:
            self.stats['fetched'] += len(values)
        return values

    def _alive(self, proxy):
        host, _, port = proxy.partition(':')
        try:
            sock = socket.create_connection((host, int(port)), timeout=self.precheck_timeout)
            sock.close()
        except Exception:                                           # noqa: BLE001
            return False
        if not self.precheck:
            return True
        # 只验隧道能建起来，不发任何认证数据
        try:
            import requests
            session = requests.Session()
            session.trust_env = False
            session.get(f"https://{self.precheck_host}/",
                        proxies={'http': f'http://{proxy}', 'https': f'http://{proxy}'},
                        timeout=(self.precheck_timeout, self.precheck_timeout),
                        verify=False, allow_redirects=False)
            return True
        except Exception:                                           # noqa: BLE001
            return False
        finally:
            try:
                session.close()
            except Exception:                                       # noqa: BLE001
                pass

    def one(self, *, attempts=6, backoff=0.6):
        """取一条可用出口；全失败返回 None（调用方退避重试，不落盘）。"""
        for _ in range(max(1, attempts)):
            values = self.fetch_batch(1)
            if not values:
                with self._lock:
                    self.stats['empty'] += 1
                time.sleep(backoff * random.uniform(0.8, 1.4))
                continue
            proxy = random.choice(values)
            if self.precheck and not self._alive(proxy):
                with self._lock:
                    self.stats['rejected'] += 1
                continue
            return proxy
        return None
