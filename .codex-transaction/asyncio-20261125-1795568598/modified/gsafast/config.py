"""配置加载与校验。"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class Config:
    accounts: str = ""
    proxy_api: str = ""
    processes: int = 4
    threads: int = 50
    accounts_per_ip: int = 9
    proxy_precheck: bool = True
    proxy_precheck_timeout: float = 4.0
    device_root: str = "./data/devices"
    device_capacity: int = 200
    device_use_limit: int = 0            # 0 = 永不丢弃
    device_round_robin: bool = True
    otp_prefetch_threads: int = 8
    otp_queue_high: int = 400
    otp_ttl_seconds: float = 300.0
    anisette_proxy: bool = False
    timeout: float = 10.0
    retries: int = 0
    limit: int = 0
    shuffle: bool = True
    fastcheck_root: str = ""
    out_dir: str = "./data/runs"
    sample_every: int = 10

    def validate(self):
        if not os.path.exists(self.accounts):
            raise SystemExit(f"账号文件不存在: {self.accounts}")
        if "{num}" not in self.proxy_api:
            raise SystemExit("proxy_api 必须包含 {num} 占位符")
        if not self.fastcheck_root or not os.path.isdir(
                os.path.join(self.fastcheck_root, "fastcheck")):
            raise SystemExit(f"fastcheck_root 下找不到 fastcheck 包: {self.fastcheck_root}")
        self.processes = max(1, int(self.processes))
        self.threads = max(1, int(self.threads))
        self.accounts_per_ip = max(1, int(self.accounts_per_ip))
        self.device_capacity = max(self.processes, int(self.device_capacity))
        self.otp_prefetch_threads = max(1, int(self.otp_prefetch_threads))
        self.otp_queue_high = max(self.threads, int(self.otp_queue_high))
        return self

    @classmethod
    def load(cls, path: str) -> "Config":
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        known = {f.name for f in cls.__dataclass_fields__.values()}
        unknown = set(raw) - known
        if unknown:
            raise SystemExit(f"conf.json 有未知字段: {sorted(unknown)}")
        return cls(**raw).validate()
