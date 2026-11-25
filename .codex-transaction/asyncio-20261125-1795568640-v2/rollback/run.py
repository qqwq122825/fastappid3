#!/usr/bin/env python3
"""入口：python3 run.py [--conf conf.json] [--limit N] [--threads N] [--processes N]"""
from __future__ import annotations

import argparse
import sys

from gsafast.config import Config
from gsafast.runner import load_accounts, run


def main():
    parser = argparse.ArgumentParser(description='GSA 快速校验（设备不丢弃 / 每线程自取 IP / 连接复用）')
    parser.add_argument('--conf', default='conf.json')
    parser.add_argument('--limit', type=int, default=None)
    parser.add_argument('--threads', type=int, default=None)
    parser.add_argument('--processes', type=int, default=None)
    parser.add_argument('--per-ip', type=int, default=None, dest='accounts_per_ip')
    parser.add_argument('--devices', type=int, default=None, help='设备槽位总数')
    parser.add_argument('--no-precheck', action='store_true')
    parser.add_argument('--no-shuffle', action='store_true')
    args = parser.parse_args()

    cfg = Config.load(args.conf)
    if args.limit is not None:
        cfg.limit = args.limit
    if args.threads:
        cfg.threads = args.threads
    if args.processes:
        cfg.processes = args.processes
    if args.accounts_per_ip:
        cfg.accounts_per_ip = args.accounts_per_ip
    if args.devices:
        cfg.device_capacity = args.devices
    if args.no_precheck:
        cfg.proxy_precheck = False
    if args.no_shuffle:
        cfg.shuffle = False
    cfg.validate()
    # 槽位必须覆盖每个线程各一台
    need = cfg.processes * cfg.threads
    if cfg.device_capacity < need:
        print(f'设备槽位 {cfg.device_capacity} < 进程×线程 {need}，自动提升到 {need}')
        cfg.device_capacity = need

    rows = load_accounts(cfg.accounts, cfg.limit, cfg.shuffle)
    if not rows:
        raise SystemExit('没有可用账号')
    run(cfg, rows)


if __name__ == '__main__':
    sys.exit(main())
