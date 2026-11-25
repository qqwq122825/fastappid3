"""多进程调度：切账号、分区设备槽位、起进程、汇总结果。"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import queue
import random
import statistics
import sys
import threading
import time

from .config import Config
from .device import DevicePool
from .gsa import Gsa
from .otp import OtpPool
from .proxy import ProxySource
from .worker import Context, Worker

ORIGIN = 'https://new.ani.sidestore.io'


def load_accounts(path, limit=0, shuffle=True):
    rows = [line.strip() for line in open(path, encoding='utf-8', errors='replace')
            if line.strip() and '----' in line]
    if shuffle:
        random.SystemRandom().shuffle(rows)
    if limit and limit < len(rows):
        rows = rows[:limit]
    parsed = []
    for index, line in enumerate(rows):
        email, _, password = line.partition('----')
        parsed.append({'row': index + 1, 'email': email.strip(), 'password': password.strip()})
    return parsed


def partition(seq, parts, index):
    """把槽位/账号切成互不重叠的连续段。"""
    total = len(seq)
    if total == 0:
        return []
    base, extra = divmod(total, parts)
    start = index * base + min(index, extra)
    size = base + (1 if index < extra else 0)
    return seq[start:start + size]


def child(args):
    index, cfg_dict, rows, slots, out_path, summary_path = args
    cfg = Config(**cfg_dict)
    gsa = Gsa(cfg.fastcheck_root)

    fc_pool = gsa.device_pool(cfg.device_root, ORIGIN, cfg.device_capacity)
    devices = DevicePool(fc_pool, capacity=cfg.device_capacity,
                         use_limit=cfg.device_use_limit)
    ready = devices.provision(slots, threads=16, timeout=max(40.0, cfg.timeout * 3))
    if not ready:
        json.dump({'index': index, 'ok': False, 'error': 'provision_failed'},
                  open(summary_path, 'w'))
        return {'index': index, 'done': 0, 'ok': False}

    proxies = ProxySource(cfg.proxy_api, precheck=cfg.proxy_precheck,
                          precheck_timeout=cfg.proxy_precheck_timeout)
    otp = OtpPool(devices, ready, per_slot=3,
                  prefetch_threads=cfg.otp_prefetch_threads,
                  ttl=cfg.otp_ttl_seconds, timeout=cfg.timeout).start()

    tasks = list(rows)
    sink = open(out_path, 'w', encoding='utf-8')
    stop = threading.Event()
    ctx = Context(cfg=cfg, gsa=gsa, devices=devices, proxies=proxies, otp=otp,
                  tasks=tasks, sink=sink, stop=stop)

    started = time.monotonic()
    workers = [Worker(i, ctx) for i in range(cfg.threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    wall = time.monotonic() - started
    stop.set()
    otp.stop()
    sink.close()

    cpu = sum(w.cpu_s for w in workers)
    counts = ctx.snapshot()
    summary = {'index': index, 'ok': True, 'slots': len(ready),
               'threads': cfg.threads, 'done': counts['done'],
               'wall_s': round(wall, 2), 'cpu_s': round(cpu, 2),
               'cpu_cores': round(cpu / wall, 2) if wall else None,
               'connections': sum(w.connections for w in workers),
               'per_worker': [w.count for w in workers],
               'by_status': counts['by_status'],
               'devices': devices.snapshot(), 'otp': otp.snapshot(),
               'proxies': dict(proxies.stats), 'backend': gsa.backend}
    json.dump(summary, open(summary_path, 'w'), ensure_ascii=False, indent=1)
    return summary


def run(cfg: Config, rows):
    os.makedirs(cfg.out_dir, exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    run_dir = os.path.join(cfg.out_dir, f'{stamp}-{os.getpid()}')
    os.makedirs(run_dir, exist_ok=True)

    slots = list(range(1, cfg.device_capacity + 1))
    jobs, paths = [], []
    for index in range(cfg.processes):
        out_path = os.path.join(run_dir, f'p{index}.jsonl')
        summary_path = os.path.join(run_dir, f'p{index}.summary.json')
        paths.append((out_path, summary_path))
        jobs.append((index, cfg.__dict__, partition(rows, cfg.processes, index),
                     partition(slots, cfg.processes, index), out_path, summary_path))

    print(f'账号 {len(rows)} 条 | {cfg.processes} 进程 × {cfg.threads} 线程 '
          f'| 设备槽位 {cfg.device_capacity} | 每 IP {cfg.accounts_per_ip} 条')
    print(f'输出 {run_dir}')
    backend = Gsa(cfg.fastcheck_root).backend
    print(f'SRP 后端: {backend}' + ('  ← gmpy2 未安装，单条 CPU 会高 7.6ms'
                                    if backend == 'python' else ''))

    started = time.monotonic()
    context = mp.get_context('spawn')
    with context.Pool(cfg.processes) as pool:
        results = pool.map(child, jobs)
    wall = time.monotonic() - started

    summarise(results, wall, run_dir)
    return run_dir


def summarise(results, wall, run_dir):
    done = sum(r.get('done') or 0 for r in results)
    cpu = sum(r.get('cpu_s') or 0 for r in results)
    status = {}
    for r in results:
        for key, value in (r.get('by_status') or {}).items():
            status[key] = status.get(key, 0) + value
    print('\n=== 汇总 ===')
    print(f'完成 {done} 条 / 墙钟 {wall:.1f}s = {done / wall if wall else 0:.1f} 条/秒 '
          f'= {done / wall * 3600 / 10000 if wall else 0:.1f} 万/小时')
    print(f'CPU {cpu:.1f}s = {cpu / wall if wall else 0:.2f} 核 '
          f'（{cpu / done * 1000 if done else 0:.1f} ms/条）')
    print(f'状态: {status}')
    conns = sum(r.get('connections') or 0 for r in results)
    if done:
        print(f'连接数 {conns}（{done / conns:.1f} 条/连接）')
    for r in results:
        if r.get('ok'):
            print(f'  p{r["index"]}: {r["done"]} 条 {r["wall_s"]}s '
                  f'CPU {r["cpu_cores"]} 核 槽位 {r["slots"]} '
                  f'OTP {r["otp"]["produced"]}产/{r["otp"]["miss"]}缺')
        else:
            print(f'  p{r["index"]}: 失败 {r.get("error")}')

    # 耗时分布
    ms = []
    for name in sorted(os.listdir(run_dir)):
        if not name.endswith('.jsonl'):
            continue
        with open(os.path.join(run_dir, name), encoding='utf-8') as handle:
            for line in handle:
                try:
                    ms.append(json.loads(line)['ms'])
                except (ValueError, KeyError):
                    pass
    if ms:
        ms.sort()
        n = len(ms)
        print(f'\n单条耗时 p50={statistics.median(ms):.0f}ms '
              f'p90={ms[int(n * .9)]:.0f}ms p99={ms[min(n - 1, int(n * .99))]:.0f}ms '
              f'max={max(ms):.0f}ms')
