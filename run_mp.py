#!/usr/bin/env python3
"""多进程调度：切分账号并共享持久设备池，起 N 个线程进程，汇总 live.json。

每个子进程使用简单线程处理网络请求和 SRP/PBKDF2 计算。

    python3 run_mp.py --processes 4 --threads 500 --limit 0
    python3 run_mp.py --processes 4 --threads 500 --limit 20000 --per-ip 6

子进程各写自己的 data/live-p{i}.json，主进程每秒合并成 data/live.json，页面照旧读它。
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
if os.path.isdir(os.path.join(HERE, 'fastcheck')):
    sys.path.insert(0, HERE)
from simple import (histogram_median, histogram_value_at, proxy_api_default,
                    write_startup_live)     # noqa: E402  凭据统一从 secrets/env 读
from fastcheck.devices import registered_device_slots  # noqa: E402
PYTHON = os.path.join(HERE, '.venv', 'bin', 'python')
DATA = os.path.join(HERE, 'data')
LIVE = os.path.join(DATA, 'live.json')
WORKER = os.path.join(HERE, 'simple.py')


def count_accounts(path):
    n = 0
    with open(path, encoding='utf-8', errors='replace') as handle:
        for line in handle:
            if line.strip() and '----' in line:
                n += 1
    return n


def build_jobs(args, total):
    # 先按"文件里真实有多少条"截断 limit，否则 limit=200 而只有 100 条时，
    # 预期总数会算成 200，任务永远停在 incomplete。
    available = max(0, total - args.offset)
    effective = available if not args.limit else min(args.limit, available)
    per = (effective + args.processes - 1) // args.processes if args.processes else 0
    jobs = []
    for index in range(args.processes):
        offset = args.offset + index * per
        left = effective - index * per
        count = min(per, left)
        if count <= 0:
            break
        jobs.append({
            'index': index,
            'offset': offset,
            'limit': count,
            'slot_base': args.slot_base + index * args.threads,
            'out': os.path.join(DATA, f'mp-p{index}.jsonl'),
            'live': os.path.join(DATA, f'live-p{index}.json'),
        })
    return jobs


def assign_device_slots(jobs, persisted_slots, slot_base=0):
    """Evenly assign persisted devices and disjoint new-slot sequences."""
    slots = sorted({int(slot) for slot in persisted_slots if int(slot) > 0})
    owner_count = max(1, len(jobs))
    first_new_slot = max(slots or [int(slot_base or 0)]) + 1
    for owner, job in enumerate(jobs):
        job['device_slots'] = slots[owner::owner_count]
        job['new_slot_start'] = first_new_slot + owner
        job['new_slot_step'] = owner_count
    return jobs


def spawn(args, jobs):
    procs = []
    for job in jobs:
        cmd = [PYTHON, WORKER,
               '--accounts', args.accounts,
               '--threads', str(args.threads),
               '--offset', str(job['offset']),
               '--limit', str(job['limit']),
               '--slot-base', str(job['slot_base']),
               '--device-root', args.device_root,
               '--device-slots', (','.join(map(str, job['device_slots'])) or '-'),
               '--new-slot-start', str(job['new_slot_start']),
               '--new-slot-step', str(job['new_slot_step']),
               '--per-ip', str(args.per_ip),
               '--otp-reuse', str(args.otp_reuse),
               '--retry', str(args.retry),
               '--item-timeout', str(args.item_timeout),
               '--ip-ttl', str(args.ip_ttl),
               '--out', job['out'],
               '--live', job['live'],
               '--timeout', str(args.timeout),
               '--register-timeout', str(args.register_timeout),
               '--device-max-uses', str(args.device_max_uses),
               '--api', args.api]
        if args.anisette_proxy:
            cmd.append('--anisette-proxy')
        cmd += ['--anisette-timeout', str(args.anisette_timeout)]
        if args.no_register:
            cmd.append('--no-register')
        if args.verify_web:
            cmd.append('--verify-web')
        if args.anisette_workers:
            cmd += ['--anisette-workers', str(args.anisette_workers)]
        log = open(os.path.join(DATA, f'mp-p{job["index"]}.log'), 'w', encoding='utf-8')
        proc = subprocess.Popen(cmd, cwd=HERE, stdout=log, stderr=subprocess.STDOUT)
        job['proc'] = proc
        procs.append(job)
        print(f'  进程 {job["index"]}: offset={job["offset"]} 条数={job["limit"]} '
              f'加载设备={len(job["device_slots"])} 新槽位={job["new_slot_start"]}'
              f'+{job["new_slot_step"]} pid={proc.pid}')
    return procs


def read_live(path):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def merge(jobs, started, expected_total=0, wall_started=None):
    if not jobs:
        return {'started': time.strftime('%H:%M:%S'), 'elapsed': 0, 'total': 0,
                'done': 0, 'rate': 0, 'per_hour': 0, 'eta': None, 'threads': 0,
                'backend': 'gmpy2', 'cpu_seconds': 0, 'cpu_cores': 0,
                'cpu_per_account': 0, 'ip_fail': 0, 'ip_pool': {},
                'by_status': {}, 'p50': None, 'p90': None, 'recent': [],
                'accounts': '', 'finished': True, 'status': 'complete',
                'incomplete': 0, 'processes': 0, 'otp_hit': 0, 'otp_fetch': 0,
                'device_ready': 0, 'device_registered': 0, 'device_in_use': 0,
                'device_registering': 0, 'register_errors': 0,
                'register_error_types': {}, 'retried': 0,
                'by_retry': {}, 'budget_hit': 0,
                'startup': {'phase': 'complete', 'message': '没有待处理账号',
                            'process_ready': 0, 'process_total': 0}}
    done = total = 0
    cpu = 0.0
    proc_cpu = 0.0
    incomplete = 0
    by_status = {}
    recent = []
    p50s, p90s = [], []
    ip_calls = fetched = blocked = 0
    pool_processes = []
    pool_available_values, pool_low_values, pool_high_values = [], [], []
    pool_supplier_states = []
    latency_hist = {}
    otp_hit = otp_fetch = 0
    retried = budget_hit = 0
    by_retry = {}
    device_ready = device_in_use = device_registering = register_errors = 0
    register_error_types = {}
    startup_rows = []
    finished = True
    finished_flag = True
    for job in jobs:
        payload = read_live(job['live'])
        if payload is None:
            finished_flag = False
            pool_processes.append({
                'process': int(job.get('index') or 0) + 1,
                'available': None, 'low_water': None, 'high_water': None,
                'supplier_alive': None,
            })
            continue
        startup_rows.append(payload.get('startup') or {})
        done += payload.get('done') or 0
        cpu += payload.get('cpu_seconds') or 0
        proc_cpu += payload.get('proc_cpu_seconds') or 0
        incomplete += payload.get('incomplete') or 0
        for key, value in (payload.get('by_status') or {}).items():
            by_status[key] = by_status.get(key, 0) + value
        for row in (payload.get('recent') or [])[-4:]:
            recent.append(row)
        weight = payload.get('done') or 0
        if payload.get('p50') and weight:
            p50s.append((payload['p50'], weight))
        if payload.get('p90') and weight:
            p90s.append((payload['p90'], weight))
        pool = payload.get('ip_pool') or {}
        process_pool = {
            'process': int(job.get('index') or 0) + 1,
            'available': pool.get('available'),
            'low_water': pool.get('low_water'),
            'high_water': pool.get('high_water'),
            'supplier_alive': pool.get('supplier_alive'),
            'api_calls': pool.get('api_calls') or 0,
            'fetched': pool.get('fetched') or 0,
            'blocked': pool.get('blocked') or 0,
        }
        pool_processes.append(process_pool)
        if pool.get('available') is not None:
            pool_available_values.append(int(pool['available']))
        if pool.get('low_water') is not None:
            pool_low_values.append(int(pool['low_water']))
        if pool.get('high_water') is not None:
            pool_high_values.append(int(pool['high_water']))
        if pool.get('supplier_alive') is not None:
            pool_supplier_states.append(bool(pool['supplier_alive']))
        for value, count in (payload.get('latency_hist') or {}).items():
            bucket = int(value)
            latency_hist[bucket] = latency_hist.get(bucket, 0) + int(count)
        otp_hit += payload.get('otp_hit') or 0
        otp_fetch += payload.get('otp_fetch') or 0
        retried += payload.get('retried') or 0
        budget_hit += payload.get('budget_hit') or 0
        for key, value in (payload.get('by_retry') or {}).items():
            by_retry[key] = by_retry.get(key, 0) + value
        # 每个子进程看到的都是同一个全局持久化设备池，取最大值
        # 即可；求和会在 2 进程时把“已注册”重复计数两次。
        device_ready = max(device_ready,
                           payload.get('device_registered',
                                       payload.get('device_ready') or 0) or 0)
        device_in_use += payload.get('device_in_use') or 0
        device_registering += payload.get('device_registering') or 0
        register_errors += payload.get('register_errors') or 0
        for key, value in (payload.get('register_error_types') or {}).items():
            register_error_types[key] = register_error_types.get(key, 0) + value
        ip_calls += pool.get('api_calls') or 0
        fetched += pool.get('fetched') or 0
        blocked += pool.get('blocked') or 0
        if not payload.get('finished'):
            finished = False
    wall_started = wall_started or time.time()
    elapsed = time.monotonic() - started
    total = expected_total or sum(j.get('limit') or 0 for j in jobs)
    recent.sort(key=lambda r: r.get('t') or 0)
    phase_priority = {
        'device_scan': 0, 'device_load': 1, 'spawning': 2,
        'proxy_fetch': 3, 'device_register': 4, 'ready': 5,
        'running': 6, 'complete': 7, 'stopped': 7,
    }
    phases = [str(row.get('phase') or 'spawning') for row in startup_rows]
    startup_phase = ('running' if done else
                     min(phases, key=lambda value: phase_priority.get(value, 2))
                     if phases else 'spawning')
    startup_messages = [str(row.get('message') or '') for row in startup_rows
                        if row.get('message')]
    startup = {
        'phase': startup_phase,
        'message': ('业务校验已开始' if done else
                    startup_messages[0] if startup_messages else '正在启动子进程'),
        'process_ready': len(startup_rows),
        'process_total': len(jobs),
    }
    for key in ('device_discovered', 'device_loaded', 'device_ready',
                'device_target', 'device_registering', 'device_in_use',
                'proxy_target', 'proxy_fetched', 'proxy_available',
                'proxy_api_calls', 'workers_started',
                'public_header_waiting', 'public_header_ready',
                'public_header_retries'):
        startup[key] = sum(int(row.get(key) or 0) for row in startup_rows)
    startup['public_header_limit'] = sum(
        int(row.get('public_header_limit') or 0) for row in startup_rows)
    return {
        'started': time.strftime('%H:%M:%S', time.localtime(wall_started)),
        'elapsed': round(elapsed, 1),
        'total': total, 'done': done,
        'rate': round(done / elapsed, 2) if elapsed else 0,
        'per_hour': round(done / elapsed * 3600) if elapsed else 0,
        'eta': round((total - done) / (done / elapsed), 0) if done and elapsed else None,
        # 页面会再显示“每进程线程 × 进程数”，这里必须保留每进程口径，
        # 不能提前乘一次，否则 2×400 会被误显示成 800×2。
        'threads': jobs[0].get('threads', 0) if jobs else 0,
        'backend': 'gmpy2', 'engine': 'threading',
        'cpu_seconds': round(cpu, 2),
        'cpu_cores': round(cpu / elapsed, 3) if elapsed else 0,
        'cpu_per_account': round(cpu / done * 1000, 1) if done else 0,
        'ip_fail': 0,
        'ip_pool': {
            'api_calls': ip_calls, 'fetched': fetched, 'blocked': blocked,
            'processes': len(jobs),
            'available': (sum(pool_available_values)
                          if pool_available_values else None),
            'low_water': (sum(pool_low_values) if pool_low_values else None),
            'high_water': (sum(pool_high_values) if pool_high_values else None),
            'supplier_alive': (all(pool_supplier_states)
                               if pool_supplier_states else None),
            'by_process': pool_processes,
        },
        'by_status': by_status,
        'p50': (round(histogram_median(latency_hist)) if latency_hist
                else round(sum(v * w for v, w in p50s) / sum(w for _, w in p50s))
                if p50s else None),
        'p90': (histogram_value_at(latency_hist, int(sum(latency_hist.values()) * .9))
                if latency_hist
                else round(sum(v * w for v, w in p90s) / sum(w for _, w in p90s))
                if p90s else None),
        'latency_hist': latency_hist,
        'p50_note': ('各进程延迟直方图合并后的总体分位数' if latency_hist
                     else '兼容旧子进程：各进程分位数按完成数加权'),
        'proc_cpu_seconds': round(proc_cpu, 2),
        'proc_cpu_cores': round(proc_cpu / elapsed, 3) if elapsed else 0,
        'incomplete': incomplete,
        'otp_hit': otp_hit, 'otp_fetch': otp_fetch,
        'retried': retried, 'by_retry': by_retry, 'budget_hit': budget_hit,
        'device_ready': device_ready,
        'device_registered': device_ready,
        'device_in_use': device_in_use,
        'device_registering': device_registering,
        'register_errors': register_errors,
        'register_error_types': register_error_types,
        'recent': recent[-12:],
        'accounts': os.path.join(DATA, 'accounts-placeholder'),
        'finished': finished and finished_flag,
        'processes': len(jobs),
        'startup': startup,
    }


def main():
    ap = argparse.ArgumentParser(description='多进程 GSA 校验（4 核机器用 4 进程吃满）')
    ap.add_argument('--accounts', default='/Users/xxx/Downloads/2026-11-23_全部结果.txt')
    ap.add_argument('--api', default=proxy_api_default(), help='代理接口，含 {num} 占位符')
    ap.add_argument('--processes', type=int, default=4)
    ap.add_argument('--threads', type=int, default=500, help='每进程并发线程数')
    ap.add_argument('--limit', type=int, default=0, help='总条数，0=全部')
    ap.add_argument('--offset', type=int, default=0)
    ap.add_argument('--slot-base', type=int, default=0, dest='slot_base')
    ap.add_argument('--device-root', default='./data/devices-simple', dest='device_root')
    ap.add_argument('--per-ip', type=int, default=1, dest='per_ip',
                    help='一条 IP 跑多少条账号（1=每个任务换新 IP，走 IP 池 rotate）')
    ap.add_argument('--otp-reuse', type=int, default=15, dest='otp_reuse',
                    help='一个公共头验多少条账号（0=每条都换）')
    ap.add_argument('--ip-ttl', type=float, default=50.0, dest='ip_ttl')
    ap.add_argument('--timeout', type=float, default=10.0)
    ap.add_argument('--item-timeout', type=float, default=20.0, dest='item_timeout',
                    help='单条账号墙钟总预算（含重试）')
    ap.add_argument('--retry', type=int, default=2,
                    help='外层重试：http=0 / 5xx / -22421 时换环境重来')
    ap.add_argument('--anisette-proxy', action='store_true', dest='anisette_proxy',
                    help='公共头走代理（机房 IP 直连 sidestore 被墙时必须开）')
    ap.add_argument('--anisette-timeout', type=float, default=20.0, dest='anisette_timeout')
    ap.add_argument('--register-timeout', type=float, default=20.0, dest='register_timeout',
                    help='设备初始化总超时，耗尽后剩余账号记为超时')
    ap.add_argument('--device-max-uses', type=int, default=100, dest='device_max_uses',
                    help='每台设备完成账号数上限，达到后销毁并注册新设备；0=不限')
    ap.add_argument('--no-register', action='store_true', dest='no_register')
    ap.add_argument('--anisette-workers', type=int, default=0, dest='anisette_workers',
                    help='并发请求公共头上限，0=不限')
    ap.add_argument('--verify-web', action='store_true', dest='verify_web',
                    help='GSA 判 au=repair 时用 web 协议细化（透传给子进程）')
    args = ap.parse_args()

    if not args.api or '{num}' not in args.api:
        raise SystemExit('没有代理接口：设置 GSA_PROXY_API 环境变量，或写 secrets.json')
    os.makedirs(DATA, exist_ok=True)
    for pattern in ('live-p*.json', 'mp-p*.jsonl'):
        for path in glob.glob(os.path.join(DATA, pattern)):
            try:
                os.remove(path)
            except OSError:
                pass

    total = count_accounts(args.accounts)
    jobs = build_jobs(args, total)
    startup_started = time.monotonic()
    write_startup_live(
        LIVE, {
            'phase': 'device_scan', 'message': '正在扫描持久化设备',
            'process_ready': 0, 'process_total': len(jobs),
            'device_discovered': 0, 'device_loaded': 0,
            'device_ready': 0, 'device_target': len(jobs) * args.threads,
            'proxy_target': 0, 'proxy_fetched': 0, 'proxy_available': 0,
        }, total=total, threads=args.threads, processes=len(jobs),
        elapsed=round(time.monotonic() - startup_started, 1))
    persisted_slots = registered_device_slots(
        args.device_root, 'https://new.ani.sidestore.io')
    # Stable disjoint ownership for this run: process 0 gets slots 0,N,2N...;
    # process 1 gets 1,N+1...  No device crosses processes.
    assign_device_slots(jobs, persisted_slots, args.slot_base)
    write_startup_live(
        LIVE, {
            'phase': 'spawning', 'message': '设备读取完成，正在启动工作进程',
            'process_ready': 0, 'process_total': len(jobs),
            'device_discovered': len(persisted_slots),
            'device_loaded': len(persisted_slots),
            'device_ready': len(persisted_slots),
            'device_target': len(jobs) * args.threads,
            'proxy_target': 0, 'proxy_fetched': 0, 'proxy_available': 0,
        }, total=total, threads=args.threads, processes=len(jobs),
        elapsed=round(time.monotonic() - startup_started, 1))
    need_slots = args.slot_base + len(jobs) * args.threads
    print(f'账号总数 {total}，切成 {len(jobs)} 个进程 × {args.threads} 线程 '
          f'= {len(jobs)*args.threads} 并发，设备池容量按需扩展（参考槽位 1-{need_slots}）')
    print(f'设备分组：磁盘已注册 {len(persisted_slots)} 台，平均加载到 {len(jobs)} 个进程；'
          '进程之间不共享设备')
    print('线程模式：优先租用本进程内使用次数最少的空闲设备；全部占用才注册新设备；任务结束即归还')
    if not jobs:
        raise SystemExit(f'没有可处理的账号：文件 {args.accounts} 在 offset={args.offset} '
                         f'之后没有记录（共 {total} 条）')
    expected_total = sum(job['limit'] for job in jobs)
    procs = spawn(args, jobs)
    for job in procs:
        job['threads'] = args.threads

    started = time.monotonic()
    wall_started = time.time()
    stop = False

    def handler(signum, frame):
        nonlocal stop
        stop = True
        for job in procs:
            try:
                job['proc'].terminate()
            except OSError:
                pass

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    try:
        while not stop:
            alive = [job for job in procs if job['proc'].poll() is None]
            payload = merge(procs, started, expected_total, wall_started)
            tmp = LIVE + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as handle:
                json.dump(payload, handle, ensure_ascii=False)
            os.replace(tmp, LIVE)
            if not alive:
                # 不能只看"进程都退了"就标完成，还要 done == total
                complete = payload['done'] >= payload['total'] > 0
                payload['finished'] = complete
                payload['status'] = 'complete' if complete else 'incomplete'
                payload['incomplete'] = max(0, payload['total'] - payload['done'])
                payload['startup'] = dict(
                    payload.get('startup') or {},
                    phase='complete' if complete else 'stopped',
                    message='任务已完成' if complete else '任务未完整完成')
                with open(LIVE, 'w', encoding='utf-8') as handle:
                    json.dump(payload, handle, ensure_ascii=False)
                break
            print(f'  {payload["done"]:>6}/{payload["total"]:<6} '
                  f'{payload["rate"]:6.2f} 条/秒 = {payload["per_hour"]/10000:5.1f} 万/小时 '
                  f'CPU {payload["cpu_cores"]:.2f} 核 {payload["cpu_per_account"]:.1f} ms/条 '
                  f'活跃进程 {len(alive)}/{len(procs)}')
            time.sleep(5)
    finally:
        # The web controller gives this parent eight seconds to stop.  Waiting
        # five seconds *per child* could exceed that window, after which the
        # parent was killed and later children became PPID-1 orphans.  Use one
        # shared deadline, then reap every remaining worker in a second pass.
        for job in procs:
            if job['proc'].poll() is None:
                job['proc'].terminate()
        deadline = time.monotonic() + 4.0
        for job in procs:
            try:
                remaining = max(0.05, deadline - time.monotonic())
                job['proc'].wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                pass
        for job in procs:
            if job['proc'].poll() is None:
                job['proc'].kill()
        for job in procs:
            try:
                job['proc'].wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass

    payload = merge(procs, started, expected_total, wall_started)   # 结束时重新汇总
    complete = payload['done'] >= payload['total'] > 0
    payload['finished'] = complete
    payload['status'] = 'complete' if complete else 'incomplete'
    payload['incomplete'] = max(0, payload['total'] - payload['done'])
    payload['startup'] = dict(
        payload.get('startup') or {},
        phase='complete' if complete else 'stopped',
        message='任务已完成' if complete else '任务未完整完成')
    with open(LIVE, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, ensure_ascii=False)
    print(f'\n完成 {payload["done"]}/{payload["total"]}  '
          f'{payload["elapsed"]}s  {payload["rate"]} 条/秒 = '
          f'{payload["per_hour"]/10000:.1f} 万/小时  CPU {payload["cpu_cores"]} 核 '
          f'{payload["cpu_per_account"]} ms/条')
    print(f'整进程 CPU {payload.get("proc_cpu_cores")} 核（各进程独立统计）')
    if payload.get('incomplete'):
        print(f'⚠ 未完成 {payload["incomplete"]} 条（不是完整批次）')
    print('状态:', payload['by_status'])


if __name__ == '__main__':
    main()
