#!/usr/bin/env python3
"""GSA 极简模型 · 控制台

    python3 web.py                 # 打开 http://127.0.0.1:8777

功能：上传账号文件 → 设线程数 → 开始/停止 → 实时看速度与 CPU。
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = os.path.join(HERE, 'data', 'live.json')
UPLOAD_DIR = os.path.join(HERE, 'data', 'uploads')
DEFAULT_ACCOUNTS = os.path.join(HERE, 'data', 'accounts.txt')
ACCOUNT_STATE = os.path.join(HERE, 'data', 'current-accounts.json')
TASK_STATE = os.path.join(HERE, 'data', 'task-process.json')
DEVICE_ROOT = os.path.join(HERE, 'data', 'devices-simple')
DEVICE_ORIGIN = 'https://new.ani.sidestore.io'
APP_VERSION = '2026.11.28.2'


NUM_RE = re.compile(r'([?&]num=)\d+')


def normalize_api(url):
    """把用户粘贴的接口地址统一成带 {num} 占位符的形式。

    ...&num=1&...          → ...&num={num}&...
    ...&num={num}&...      → 原样
    ...（没有 num 参数）   → 自动补 &num={num}
    """
    url = (url or '').strip()
    if not url:
        return ''
    if '{num}' in url:
        return url
    if NUM_RE.search(url):
        return NUM_RE.sub(r'\1{num}', url)
    return url + ('&' if '?' in url else '?') + 'num={num}'


def mask_api(url):
    """页面展示用：遮掉 password / token 的值。"""
    if not url:
        return ''
    masked = re.sub(r'(?i)(://[^:/@\s]+:)[^@\s]+@', r'\1***@', str(url))
    return re.sub(r'(?i)((?:password|passwd|pwd|token|key)=)[^&\s]+',
                  r'\1***', masked)


def save_api(url):
    path = os.path.join(HERE, 'secrets.json')
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except FileNotFoundError:
        data = {}
    except json.JSONDecodeError as exc:
        raise ValueError(
            f'secrets.json 格式错误（第 {exc.lineno} 行第 {exc.colno} 列），原文件未修改') from exc
    if not isinstance(data, dict):
        raise ValueError('secrets.json 顶层必须是 JSON 对象，原文件未修改')
    data['proxy_api'] = url
    tmp = path + '.tmp'
    descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=1)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def validate_proxy_api(url, timeout=8.0):
    """Reject supplier error pages before replacing the working credential."""
    target = str(url).replace('{num}', '1')
    try:
        with urllib.request.urlopen(target, timeout=float(timeout)) as response:
            body = response.read(4096).decode('utf-8', 'replace').strip()
    except Exception as exc:                                      # noqa: BLE001
        raise ValueError(f'接口无法访问：{type(exc).__name__}') from exc
    if not re.search(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}:\d+(?!\d)', body):
        reason = re.sub(r'(?i)(password|passwd|pwd|token|key)=[^&\s]+',
                        r'\1=***', body[:120])
        raise ValueError(f'供应商未返回代理：{reason or "空响应"}')
    return True


def command_for_log(cmd):
    """Return a shell-readable command with credential-bearing values removed."""
    safe = []
    redact_next = False
    for value in cmd:
        text = str(value)
        if redact_next:
            safe.append('<proxy-api-redacted>')
            redact_next = False
            continue
        safe.append(text)
        if text == '--api':
            redact_next = True
    return shlex.join(safe)


def proxy_api():
    """凭据不进源码：环境变量优先，其次 secrets.json / conf.json。"""
    import os as _os
    env = _os.environ.get('GSA_PROXY_API')
    if env:
        return env
    for name in ('secrets.json', 'conf.json'):
        path = _os.path.join(HERE, name)
        try:
            with open(path, encoding='utf-8') as handle:
                value = json.load(handle).get('proxy_api')
            if isinstance(value, str) and '{num}' in value:
                return value
        except (OSError, ValueError):
            continue
    return ''
PYTHON = os.path.join(HERE, '.venv', 'bin', 'python')
MAX_THREADS = 2000

STATE = {
    'accounts': DEFAULT_ACCOUNTS,
    'proc': None,
    'threads': 0,
    'limit': 0,
    'started': None,
    'log': os.path.join(HERE, 'data', 'run.log'),
    'pending_accounts': None,
    'take_pending': False,
    'run_out': '',          # 本轮结果文件（每次任务独立，避免和历史混在一起）
    'started_at': 0.0,      # 本轮开始的 epoch 秒
    'total': 0,             # 本轮预期总数，live.json 尚未生成时也可用
    'processes': 1,
}
_ACCOUNT_CACHE = {}
_LOCK = threading.Lock()
PASSWORD = 'mtx123'          # 默认密码，--password 或 GSA_PASSWORD 可改


def _persistent_account_path(path):
    """只接受服务器 data/accounts.txt 或 data/uploads/ 里的文件。"""
    if not path:
        return None
    real = os.path.realpath(str(path))
    uploads = os.path.realpath(UPLOAD_DIR)
    try:
        in_uploads = os.path.commonpath((real, uploads)) == uploads
    except ValueError:
        in_uploads = False
    if real == os.path.realpath(DEFAULT_ACCOUNTS) or in_uploads:
        return real
    return None


def _remember_accounts(path):
    """记住最后一次上传，web 服务重启后仍能找到。"""
    path = _persistent_account_path(path)
    if not path or not os.path.isfile(path):
        return
    os.makedirs(os.path.dirname(ACCOUNT_STATE), exist_ok=True)
    tmp = ACCOUNT_STATE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump({'accounts': path}, handle, ensure_ascii=False)
    os.replace(tmp, ACCOUNT_STATE)


def _startup_accounts():
    """优先恢复记住的文件，其次选 uploads 里最新的文件。"""
    try:
        with open(ACCOUNT_STATE, encoding='utf-8') as handle:
            saved = json.load(handle).get('accounts')
        saved = _persistent_account_path(saved)
        if saved and os.path.isfile(saved):
            return saved
    except (OSError, ValueError, AttributeError):
        pass
    try:
        files = [os.path.join(UPLOAD_DIR, name) for name in os.listdir(UPLOAD_DIR)]
        files = [path for path in files if os.path.isfile(path)]
        if files:
            return max(files, key=os.path.getmtime)
    except OSError:
        pass
    return DEFAULT_ACCOUNTS


def _cookie_token():
    import hashlib
    return hashlib.sha256(('gsa|' + PASSWORD).encode()).hexdigest()[:32]


# ---------------------------------------------------------------- 账号解析
def analyse_accounts(path):
    import collections
    if not path or not os.path.exists(path):
        return {'error': f'文件不存在: {path}', 'path': path}
    try:
        mtime = os.path.getmtime(path)
    except OSError as exc:
        return {'error': f'无法读取: {exc}', 'path': path}
    if _ACCOUNT_CACHE.get('path') == path and _ACCOUNT_CACHE.get('mtime') == mtime:
        return _ACCOUNT_CACHE['data']
    domains, lengths = collections.Counter(), collections.Counter()
    total = bad = pw_eq = 0
    samples = []
    with open(path, encoding='utf-8', errors='replace') as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            total += 1
            if '----' not in line:
                bad += 1
                continue
            account, _, password = line.partition('----')
            local, _, domain = account.partition('@')
            domains[domain.lower() or '<no-at>'] += 1
            if password and password.lower() == local.lower():
                pw_eq += 1
            lengths[len(password)] += 1
            if len(samples) < 3:
                samples.append(account)
    data = {
        'path': path, 'name': os.path.basename(path), 'total': total,
        'unique_domains': len(domains), 'top_domains': domains.most_common(6),
        'format_error': bad, 'password_equals_account': pw_eq,
        'password_equals_ratio': round(pw_eq / total * 100, 1) if total else 0,
        'length_top': lengths.most_common(5), 'samples': samples,
        'size': os.path.getsize(path),
    }
    _ACCOUNT_CACHE.update(path=path, mtime=mtime, data=data)
    return data


def read_live():
    """Return the same resilient state used by the controller internals.

    The browser polls ``/api/live``.  Keeping a second implementation here
    bypassed the stale-live JSONL fallback and made the page look empty while
    the task was still producing results.
    """
    return live_state()


def _path_allowed(path):
    """只允许访问当前任务使用的文件，或 data/uploads 下的上传文件。"""
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    if real == os.path.realpath(STATE['accounts']):
        return True
    uploads = os.path.realpath(UPLOAD_DIR)
    return real.startswith(uploads + os.sep) or real == uploads


def is_running():
    return _active_task_record() is not None


def _pid_start_token(pid):
    """Linux PID identity token; prevents killing an unrelated reused PID."""
    try:
        raw = open(f'/proc/{int(pid)}/stat', encoding='utf-8').read()
        return raw.rsplit(') ', 1)[1].split()[19]
    except (OSError, ValueError, IndexError):
        return None


def _group_alive(pgid):
    try:
        os.killpg(int(pgid), 0)
    except (OSError, ValueError):
        return False
    # killpg(..., 0) also succeeds while the group only contains zombies.
    # A persisted task has no Popen handle after the web controller restarts,
    # so waiting for init to reap those zombies made Stop block for the whole
    # grace period.  Linux /proc lets us distinguish a live member from Z.
    if os.path.isdir('/proc'):
        return _linux_group_has_live_member(pgid)
    return True


def _linux_group_has_live_member(pgid, proc_root='/proc'):
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return True
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, name, 'stat'),
                      encoding='utf-8') as handle:
                raw = handle.read()
            fields = raw.rsplit(') ', 1)[1].split()
            state, group = fields[0], int(fields[2])
        except (OSError, ValueError, IndexError):
            continue
        if group == int(pgid) and state != 'Z':
            return True
    return False


def _read_task_record():
    try:
        with open(TASK_STATE, encoding='utf-8') as handle:
            record = json.load(handle)
        return record if isinstance(record, dict) else None
    except (OSError, ValueError):
        return None


def _write_task_record(record):
    os.makedirs(os.path.dirname(TASK_STATE), exist_ok=True)
    tmp = TASK_STATE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(record, handle, ensure_ascii=False)
    os.replace(tmp, TASK_STATE)


def _clear_task_record():
    try:
        os.remove(TASK_STATE)
    except OSError:
        pass


def _active_task_record():
    """Return the live task even after this web controller was restarted."""
    proc = STATE.get('proc')
    if proc is not None and proc.poll() is None:
        record = _read_task_record() or {'pid': proc.pid, 'pgid': proc.pid}
        return record
    record = _read_task_record()
    if not record:
        return None
    try:
        pid, pgid = int(record['pid']), int(record['pgid'])
    except (KeyError, TypeError, ValueError):
        _clear_task_record()
        return None
    if pid <= 1 or pgid <= 1 or not _group_alive(pgid):
        _clear_task_record()
        return None
    expected = record.get('pid_start')
    actual = _pid_start_token(pid)
    if expected and actual and expected != actual:
        _clear_task_record()
        return None
    for key in ('accounts', 'threads', 'limit', 'total', 'processes',
                'started', 'started_at', 'run_out'):
        if key in record:
            STATE[key] = record[key]
    return record


def _running_pid():
    record = _active_task_record()
    return int(record['pid']) if record else None


_PROCESS_CPU = {'pid': None, 'at': None, 'seconds': None, 'cores': None}
_PROCESS_CPU_LOCK = threading.Lock()


def _parse_cpu_time(value):
    """Parse ``ps -o time=`` (MM:SS.xx or HH:MM:SS.xx) into seconds."""
    parts = str(value or '').strip().split(':')
    try:
        if len(parts) == 2:
            return float(parts[0]) * 60 + float(parts[1])
        if len(parts) == 3:
            return float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
    except ValueError:
        pass
    return None


def _process_cpu_seconds(pid):
    """Read cumulative CPU time for another process without extra packages."""
    pid = int(pid)
    if os.path.isdir('/proc'):
        try:
            raw = open(f'/proc/{pid}/stat', encoding='utf-8').read()
            fields = raw.rsplit(') ', 1)[1].split()
            ticks = float(os.sysconf('SC_CLK_TCK'))
            return (float(fields[11]) + float(fields[12])) / ticks
        except (OSError, ValueError, IndexError):
            return None
    if os.name == 'posix':
        try:
            result = subprocess.run(
                ['ps', '-p', str(pid), '-o', 'time='], capture_output=True,
                text=True, timeout=0.5, check=False)
            return _parse_cpu_time(result.stdout) if result.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None
    return None


def _process_group_cpu_seconds(pgid):
    """Sum CPU time for every live member of a Linux process group."""
    if not os.path.isdir('/proc'):
        return None
    ticks = float(os.sysconf('SC_CLK_TCK'))
    total = 0.0
    found = False
    try:
        entries = os.listdir('/proc')
    except OSError:
        return None
    for name in entries:
        if not name.isdigit():
            continue
        try:
            raw = open(f'/proc/{name}/stat', encoding='utf-8').read()
            fields = raw.rsplit(') ', 1)[1].split()
            if int(fields[2]) != int(pgid):
                continue
            total += (float(fields[11]) + float(fields[12])) / ticks
            found = True
        except (OSError, ValueError, IndexError):
            continue
    return total if found else None


def _process_cpu_now(pid, pgid=None):
    """Return rolling cores for the whole task process group when available."""
    now = time.monotonic()
    identity = int(pgid or pid)
    with _PROCESS_CPU_LOCK:
        if _PROCESS_CPU['pid'] == identity and _PROCESS_CPU['at'] is not None \
                and now - _PROCESS_CPU['at'] < 0.75:
            return _PROCESS_CPU['cores']
        seconds = (_process_group_cpu_seconds(pgid) if pgid is not None
                   else _process_cpu_seconds(pid))
        if seconds is None and pgid is not None:
            seconds = _process_cpu_seconds(pid)
        if seconds is None:
            return None
        cores = None
        if (_PROCESS_CPU['pid'] == identity and _PROCESS_CPU['at'] is not None
                and now > _PROCESS_CPU['at'] and seconds >= _PROCESS_CPU['seconds']):
            cores = (seconds - _PROCESS_CPU['seconds']) / (now - _PROCESS_CPU['at'])
        _PROCESS_CPU.update(pid=identity, at=now, seconds=seconds, cores=cores)
        return cores


_LIVE_CACHE = {'at': 0.0, 'data': None}
_RESULT_PROGRESS = {'key': None, 'offset': 0, 'done': 0, 'tail': b'',
                    'by_status': {}, 'recent': collections.deque(maxlen=12)}
_RESULT_PROGRESS_LOCK = threading.Lock()


def _result_progress(path):
    """增量统计 JSONL，并保留状态分布与最近结果。

    高并发工作线程可能让 live writer 长时间抢不到状态锁；结果文件
    仍在持续追加。这里只读上次 offset 之后的字节，避免每次刷新都重扫
    整个大文件。
    """
    if not path:
        return {'done': 0, 'by_status': {}, 'recent': []}
    try:
        stat = os.stat(path)
        key = (os.path.realpath(path), stat.st_dev, stat.st_ino)
    except OSError:
        return {'done': 0, 'by_status': {}, 'recent': []}
    with _RESULT_PROGRESS_LOCK:
        if (_RESULT_PROGRESS['key'] != key
                or stat.st_size < _RESULT_PROGRESS['offset']):
            _RESULT_PROGRESS.update(key=key, offset=0, done=0, tail=b'',
                                    by_status={},
                                    recent=collections.deque(maxlen=12))
        try:
            with open(path, 'rb') as handle:
                handle.seek(_RESULT_PROGRESS['offset'])
                data = _RESULT_PROGRESS['tail']
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    data += chunk
                    lines = data.split(b'\n')
                    data = lines.pop()
                    for raw in lines:
                        if not raw.strip():
                            continue
                        try:
                            row = json.loads(raw.decode('utf-8', 'replace'))
                        except (ValueError, TypeError):
                            continue
                        if not isinstance(row, dict):
                            continue
                        _RESULT_PROGRESS['done'] += 1
                        status = str(row.get('status') or 'unknown')
                        by_status = _RESULT_PROGRESS['by_status']
                        by_status[status] = by_status.get(status, 0) + 1
                        _RESULT_PROGRESS['recent'].append(row)
                _RESULT_PROGRESS['offset'] = handle.tell()
                _RESULT_PROGRESS['tail'] = data
        except OSError:
            pass
        return {'done': _RESULT_PROGRESS['done'],
                'by_status': dict(_RESULT_PROGRESS['by_status']),
                'recent': list(_RESULT_PROGRESS['recent'])}


def _expected_total(record):
    total = int(record.get('total') or STATE.get('total') or 0)
    if total:
        return total
    accounts = record.get('accounts') or STATE.get('accounts')
    analysed = analyse_accounts(accounts)
    available = (max(0, int(analysed.get('total') or 0)
                     - int(analysed.get('format_error') or 0))
                 if isinstance(analysed, dict) else 0)
    limit = int(record.get('limit') or STATE.get('limit') or 0)
    return min(limit, available) if limit else available


def live_state():
    """0.5 秒内的重复请求直接给缓存，避免多标签页把读盘打满。"""
    now = time.monotonic()
    if _LIVE_CACHE['data'] is not None and now - _LIVE_CACHE['at'] < 0.5:
        return _LIVE_CACHE['data']
    data = _live_state_uncached()
    _LIVE_CACHE.update(at=now, data=data)
    return data


def _multiprocess_ip_pool(live, data_dir=None):
    """为旧版 run_mp 汇总补齐每个子进程的 IP 池快照。"""
    live = dict(live) if isinstance(live, dict) else {}
    processes = max(1, int(live.get('processes') or 1))
    if processes <= 1:
        return live
    pool = dict(live.get('ip_pool') or {})
    rows = pool.get('by_process')
    if not isinstance(rows, list) or len(rows) < processes:
        rows = []
        directory = data_dir or os.path.join(HERE, 'data')
        for index in range(processes):
            try:
                with open(os.path.join(directory, f'live-p{index}.json'),
                          encoding='utf-8') as handle:
                    payload = json.load(handle)
                child = payload.get('ip_pool') or {}
            except (OSError, ValueError, AttributeError):
                child = {}
            rows.append({
                'process': index + 1,
                'available': child.get('available'),
                'low_water': child.get('low_water'),
                'high_water': child.get('high_water'),
                'supplier_alive': child.get('supplier_alive'),
                'api_calls': child.get('api_calls') or 0,
                'fetched': child.get('fetched') or 0,
                'blocked': child.get('blocked') or 0,
            })
    for key in ('available', 'low_water', 'high_water'):
        values = [int(row[key]) for row in rows if row.get(key) is not None]
        pool[key] = sum(values) if values else None
    states = [bool(row['supplier_alive']) for row in rows
              if row.get('supplier_alive') is not None]
    pool['supplier_alive'] = all(states) if states else None
    pool['processes'] = processes
    pool['by_process'] = rows
    live['ip_pool'] = pool
    return live


def _live_state_uncached():
    record = _active_task_record()
    running = record is not None
    try:
        with open(LIVE, encoding='utf-8') as handle:
            live = json.load(handle)
    except (OSError, ValueError):
        live = {}
    live = dict(live) if isinstance(live, dict) else {}
    # live writer 被大量工作线程饿饿时，用已落盘结果补齐进度。
    # 不修改工作进程，也不读取账号内容。
    try:
        stale = time.time() - os.path.getmtime(LIVE) > 3.0
    except OSError:
        stale = True
    progress = (_result_progress(record.get('run_out') or STATE.get('run_out'))
                if running else None)
    if running and stale:
        live_done = int(live.get('done') or 0)
        done = max(live_done, int(progress['done']))
        started_at = float(record.get('started_at') or STATE.get('started_at')
                           or time.time())
        elapsed = max(float(live.get('elapsed') or 0),
                      time.time() - started_at, 0.001)
        rate = done / elapsed
        live.update(done=done, elapsed=round(elapsed, 1),
                    rate=round(rate, 2), per_hour=round(rate * 3600),
                    live_fallback=True)
        if int(progress['done']) >= live_done:
            live['by_status'] = progress['by_status']
            live['recent'] = progress['recent']
        total = max(int(live.get('total') or 0), _expected_total(record), done)
        live.update(total=total,
                    threads=int(record.get('threads') or STATE.get('threads') or 0),
                    processes=int(record.get('processes') or STATE.get('processes') or 1),
                    started=time.strftime('%H:%M:%S', time.localtime(started_at)),
                    engine=live.get('engine') or 'threading')
        if not live.get('backend'):
            try:
                from fastcheck.protocols.srp_auth import SRP_MATH_BACKEND
                live['backend'] = SRP_MATH_BACKEND
            except ImportError:
                pass
        if total and done:
            live['eta'] = round(max(0, total - done) / rate, 0)
    # Even while live.json is fresh, never let it move the browser behind rows
    # already persisted in the current result file.  A starved live writer can
    # resume with an older snapshot after the fallback has advanced farther.
    if running and int(progress['done']) > int(live.get('done') or 0):
        live['done'] = int(progress['done'])
        live['by_status'] = progress['by_status']
        live['recent'] = progress['recent']
        live['total'] = max(int(live.get('total') or 0),
                            _expected_total(record), int(progress['done']))
    live = _multiprocess_ip_pool(live)
    live['running'] = running
    live['pid'] = int(record['pid']) if running else None
    live['version'] = APP_VERSION
    if not running:
        # live.json 是上一轮的快照，停机时应以磁盘上的持久设备池为准。
        # 只数本项目设备目录，不导入工作进程依赖，页面首次打开也能立即显示。
        idle_devices = _count_device_slots()
        live.update(device_total=idle_devices,
                    device_registered=idle_devices, device_ready=idle_devices,
                    device_in_use=0, device_registering=0)
    if running:
        current_cores = _process_cpu_now(record['pid'], record.get('pgid'))
        if current_cores is not None:
            live['proc_cpu_now'] = round(current_cores, 2)
    live['accounts'] = STATE['accounts']
    if not live.get('total') and not running:
        live.setdefault('error', 'live.json 还没生成，先点「开始」')
    return live


# ---------------------------------------------------------------- 任务控制
def start_job(accounts, threads, limit, processes=1, verify_web=False,
              per_ip=6, ip_ttl=50.0, timeout=25.0, anisette_workers=0,
              no_register=False, retry=2, item_timeout=40.0, anisette_proxy=False,
              device_max_uses=100, anisette_timeout=20.0):
    if is_running():
        return {'error': '已有任务在跑，先停止'}
    if STATE.get('take_pending') and STATE.get('pending_accounts'):
        accounts = STATE['pending_accounts']           # 点"开始"才切换到新文件
        STATE['take_pending'] = False
    if not os.path.exists(accounts):
        return {'error': f'账号文件不存在: {accounts}'}
    threads = max(1, min(int(threads or 0), MAX_THREADS))
    limit = max(0, int(limit or 0))
    account_info = analyse_accounts(accounts)
    account_total = max(0, int(account_info.get('total') or 0)
                        - int(account_info.get('format_error') or 0))
    total = min(limit, account_total) if limit else account_total
    os.makedirs(os.path.dirname(LIVE), exist_ok=True)
    processes = max(1, min(int(processes or 1), 8))
    _reset_run_artifacts(processes)
    run_out = os.path.join(HERE, 'data', f'run-{int(time.time())}.jsonl')
    STATE['run_out'] = run_out
    STATE['started_at'] = time.time()
    # Publish a synchronous first frame before spawning Python workers.  The
    # browser polls immediately after the Start response, so it must never sit
    # on an empty/stale live.json while imports, account slicing or process
    # creation are still happening.
    discovered_devices = _count_device_slots()
    initial_live = {
        'started': time.strftime('%H:%M:%S'), 'elapsed': 0,
        'total': total, 'done': 0, 'rate': 0, 'per_hour': 0,
        'threads': threads, 'processes': processes,
        'by_status': {}, 'recent': [], 'finished': False,
        'startup': {
            'phase': 'device_scan', 'message': '已接收任务，正在读取设备池',
            'process_ready': 0, 'process_total': processes,
            'device_discovered': discovered_devices,
            'device_loaded': 0, 'device_ready': 0,
            'device_target': min(total, threads * processes),
            'device_registering': 0,
            'proxy_target': 0, 'proxy_fetched': 0,
            'proxy_available': 0, 'proxy_api_calls': 0,
            'public_header_retries': 0,
        },
    }
    live_tmp = LIVE + '.tmp'
    with open(live_tmp, 'w', encoding='utf-8') as handle:
        json.dump(initial_live, handle, ensure_ascii=False)
    os.replace(live_tmp, LIVE)
    if processes > 1:
        # 多进程分配账号与设备槽位；每个子进程内使用简单线程。
        cmd = [PYTHON, os.path.join(HERE, 'run_mp.py'),
               '--accounts', accounts, '--processes', str(processes),
               '--threads', str(threads)]
        cmd += ['--limit', str(limit)]
        api = proxy_api()
        if not api:
            return {'error': '没有代理接口：请设置环境变量 GSA_PROXY_API 或写 secrets.json'}
        cmd += ['--api', api]
        if verify_web:
            cmd.append('--verify-web')
        cmd += ['--per-ip', str(per_ip), '--ip-ttl', str(ip_ttl),
                '--timeout', str(timeout), '--retry', str(retry),
                '--item-timeout', str(item_timeout),
                '--anisette-timeout', str(max(1.0, float(anisette_timeout))),
                '--device-max-uses', str(max(0, int(device_max_uses or 0)))]
        # run_mp 不接受 --out，子进程文件名由它自己生成（mp-p*.jsonl）
        if anisette_workers:
            cmd += ['--anisette-workers', str(anisette_workers)]
        if no_register:
            cmd.append('--no-register')
        if anisette_proxy:
            cmd.append('--anisette-proxy')
    else:
        cmd = [PYTHON, os.path.join(HERE, 'simple.py'),
               '--accounts', accounts, '--threads', str(threads),
               '--live', LIVE, '--limit', str(limit),
               '--out', run_out,
               '--per-ip', str(per_ip), '--ip-ttl', str(ip_ttl),
               '--timeout', str(timeout), '--retry', str(retry),
               '--item-timeout', str(item_timeout),
               '--anisette-timeout', str(max(1.0, float(anisette_timeout))),
               '--device-max-uses', str(max(0, int(device_max_uses or 0)))]
        if verify_web:
            cmd.append('--verify-web')
        if anisette_workers:
            cmd += ['--anisette-workers', str(anisette_workers)]
        if no_register:
            cmd.append('--no-register')
        if anisette_proxy:
            cmd.append('--anisette-proxy')
    # 追加而不是覆盖：否则上一次的报错会被这次清空，排查时看不到
    log = open(STATE['log'], 'a', encoding='utf-8')
    log.write(f'\n===== 启动 {time.strftime("%F %T")} =====\n')
    log.write(command_for_log(cmd) + '\n')
    log.flush()
    # One task owns one process group.  run_mp.py and every simple.py child
    # inherit it, so Stop can terminate the whole tree with one signal.
    proc = subprocess.Popen(cmd, cwd=HERE, stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    STATE.update(proc=proc, accounts=accounts, threads=threads, limit=limit,
                 total=total, processes=processes, started=time.time(),
                 pending_accounts=None)
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = proc.pid
    _write_task_record({
        'pid': proc.pid, 'pgid': pgid, 'pid_start': _pid_start_token(proc.pid),
        'accounts': accounts, 'threads': threads, 'limit': limit, 'total': total,
        'processes': processes, 'started': STATE['started'],
        'started_at': STATE['started_at'], 'run_out': STATE['run_out'],
    })
    total_threads = threads * processes
    return {'ok': True, 'pid': proc.pid, 'threads': threads, 'processes': processes,
            'limit': limit, 'total': total, 'total_threads': total_threads,
            'warmup_hint': (f'已启动 {processes} 进程 × {threads} 线程 = {total_threads} 并发；'
                            '线程已并发启动，设备、代理、公共头进展实时显示')}


def _count_device_slots():
    """Return the current persistent device count without worker imports."""
    device_key = hashlib.sha256(DEVICE_ORIGIN.encode()).hexdigest()[:24]
    device_dir = os.path.join(DEVICE_ROOT, device_key, 'devices')
    try:
        return sum(1 for item in os.scandir(device_dir) if item.is_dir())
    except OSError:
        return 0


def _reset_run_artifacts(processes):
    """Synchronously remove the previous run before a new worker can be polled."""
    import glob
    paths = [LIVE]
    if int(processes) > 1:
        paths.extend(glob.glob(os.path.join(HERE, 'data', 'live-p*.json')))
        paths.extend(glob.glob(os.path.join(HERE, 'data', 'mp-p*.jsonl')))
    for path in paths:
        try:
            os.remove(path)
        except OSError:
            pass
    _LIVE_CACHE.update(at=0.0, data=None)


def clear_devices():
    """Remove only this project's persistent device pool while it is idle."""
    if is_running():
        return {'error': '任务运行中，请先停止任务再清空设备'}
    root = os.path.realpath(DEVICE_ROOT)
    data_root = os.path.realpath(os.path.join(HERE, 'data'))
    if root == data_root or not root.startswith(data_root + os.sep):
        return {'error': '设备目录不安全，已拒绝清空'}
    if os.path.islink(DEVICE_ROOT):
        return {'error': '设备目录是符号链接，已拒绝清空'}
    if not os.path.exists(root):
        cleared = 0
        _clear_live_device_counts()
        return {'ok': True, 'cleared': cleared}
    # Keep this maintenance endpoint independent from worker-only packages:
    # the web interpreter may not have portalocker installed.  Counting slot
    # directories is sufficient because the whole project-owned pool is
    # removed immediately afterwards.
    key = hashlib.sha256(DEVICE_ORIGIN.encode()).hexdigest()[:24]
    devices = os.path.join(root, key, 'devices')
    try:
        cleared = sum(1 for entry in os.scandir(devices) if entry.is_dir())
    except OSError:
        cleared = 0
    tombstone = f'{root}.clearing-{os.getpid()}-{time.time_ns()}'
    os.replace(root, tombstone)
    try:
        shutil.rmtree(tombstone)
    except OSError as exc:
        return {'error': f'设备目录已移出，但清理失败：{type(exc).__name__}'}
    _clear_live_device_counts()
    return {'ok': True, 'cleared': cleared}


def _clear_live_device_counts():
    """Keep an idle dashboard consistent with the pool removed on disk."""
    try:
        with open(LIVE, encoding='utf-8') as handle:
            live = json.load(handle)
        if isinstance(live, dict):
            live.update(device_registered=0, device_ready=0,
                        device_in_use=0, device_registering=0)
            tmp = LIVE + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as handle:
                json.dump(live, handle, ensure_ascii=False)
            os.replace(tmp, LIVE)
    except (OSError, ValueError, TypeError):
        pass
    _LIVE_CACHE.update(at=0.0, data=None)


def stop_job():
    record = _active_task_record()
    if not record:
        return {'error': '没有正在跑的任务'}
    pid, pgid = int(record['pid']), int(record['pgid'])
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    proc = STATE.get('proc')
    # SIGTERM normally ends the worker immediately.  Two seconds is enough for
    # buffers/final state, while keeping the Stop request responsive.
    deadline = time.monotonic() + 2.0
    while _group_alive(pgid) and time.monotonic() < deadline:
        if proc is not None:
            proc.poll()  # reap the direct child so a zombie cannot keep the group "alive"
        time.sleep(0.05)
    forced = _group_alive(pgid)
    if forced:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if proc is not None:
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
    stopped = not _group_alive(pgid)
    if stopped:
        _clear_task_record()
        STATE['proc'] = None
    _LIVE_CACHE.update(at=0.0, data=None)
    return {'ok': stopped, 'pid': pid, 'pgid': pgid, 'forced': forced,
            **({} if stopped else {'error': '任务进程组仍未退出'})}


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _send(self, body: bytes, ctype='application/json; charset=utf-8'):
        # The Tencent public path occasionally leaves a reused HTTP/1.1
        # connection half-open while the 29 KiB inline page is being sent.
        # Compress the document and close only that response; API polling can
        # keep using persistent connections normally.
        is_page = ctype.lower().startswith('text/html')
        encoded = is_page and 'gzip' in (self.headers.get('Accept-Encoding') or '').lower()
        if encoded:
            import gzip
            body = gzip.compress(body, compresslevel=6)
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control', 'no-store')
        if encoded:
            self.send_header('Content-Encoding', 'gzip')
            self.send_header('Vary', 'Accept-Encoding')
        if is_page:
            self.close_connection = True
        if self.close_connection:
            self.send_header('Connection', 'close')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value):
        self._send(json.dumps(value, ensure_ascii=False).encode('utf-8'))

    def do_GET(self):
        try:
            return self._do_get()
        except Exception as exc:                                   # noqa: BLE001
            import traceback
            err = traceback.format_exc()
            log_path = os.path.join(HERE, 'data', 'web-error.log')
            try:
                os.makedirs(os.path.dirname(log_path), exist_ok=True)
                with open(log_path, 'a', encoding='utf-8') as handle:
                    handle.write(f'--- {time.strftime("%F %T")} GET {self.path}\n{err}\n')
            except OSError:
                pass
            try:
                return self._json({'error': f'后端异常：{type(exc).__name__}: {exc}'})
            except Exception:
                pass

    def _do_get(self):
        if self.path.startswith('/api/') and not self._authorized():
            return self._json({'error': '请先输入密码', 'need_login': True})
        if self.path.startswith('/api/results'):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            return self._json(self._results(
                (q.get('status') or ['all'])[0],
                int((q.get('limit') or ['60'])[0] or 60),
                (q.get('query') or [''])[0]))
        if self.path.startswith('/api/export'):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            want = (q.get('status') or [''])[0].strip()
            fmt = (q.get('fmt') or ['txt'])[0]
            return self._export(want, fmt)
        if self.path.startswith('/api/api-config'):
            current = proxy_api()
            return self._json({'api': mask_api(current),
                               'has_num': '{num}' in (current or ''),
                               'configured': bool(current)})
        if self.path.startswith('/api/live'):
            return self._json(read_live())
        if self.path.startswith('/api/accounts'):
            from urllib.parse import urlparse, parse_qs
            query = parse_qs(urlparse(self.path).query)
            default = STATE['accounts']
            target = (query.get('path') or [default])[0] or default
            if not _path_allowed(target):
                return self._json({'error': '只允许读取当前任务文件或 uploads 目录下的文件'})
            return self._json(analyse_accounts(target))
        if self.path.startswith('/api/state'):
            return self._json({'running': is_running(),
                               'accounts': STATE['accounts'],
                               'threads': STATE['threads'], 'limit': STATE['limit'],
                               'pid': _running_pid(),
                               'log_tail': tail_log()})
        self._send(PAGE.encode('utf-8'), 'text/html; charset=utf-8')

    def _results(self, want, limit=60, query=''):
        """按状态查**当前任务**的结果。

        jsonl 是追加写的，历史批次都堆在同一个文件里；如果不过滤，
        页面筛出 2 万条超时、而顶部只有 3 条，因为顶部只统计当前任务。
        这里用 STATE['started'] 做下界：只保留本轮开始后写入的行。
        """
        import glob as _glob
        limit = max(1, min(500, int(limit)))
        want = (want or 'all').strip()
        query = str(query or '').strip()[:128].casefold()
        cutoff = STATE.get('started_at') or 0
        own = STATE.get('run_out') or ''
        if own and os.path.exists(own):
            # 单进程：本轮就是一个文件，直接读全量
            paths = [own]
        else:
            # 多进程：只读本轮开始后写过的 mp-p*.jsonl
            paths = sorted(_glob.glob(os.path.join(HERE, 'data', 'mp-p*.jsonl')))
        # Scan the complete current-run file.  The previous 4 MiB tail read
        # made the cumulative counters disagree with filtered rows once an
        # uncommon result (for example ``undetermined``) scrolled out of the
        # tail.  Keep only the newest requested rows in memory while counting
        # every matching result.
        out, seen, total = collections.deque(maxlen=limit), set(), 0
        if True:
            for path in paths:
                try:
                    if cutoff and os.path.getmtime(path) < cutoff - 5:
                        continue
                except OSError:
                    continue
                try:
                    handle = open(path, encoding='utf-8', errors='replace')
                except OSError:
                    continue
                with handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            r = json.loads(line)
                        except ValueError:
                            continue
                        st = str(r.get('status') or '')
                        email = str(r.get('email') or '')
                        if query and query not in email.casefold():
                            continue
                        if want == 'other':
                            if st not in ('undetermined', 'error', 'need_mac'):
                                continue
                        elif want not in ('', 'all') and st != want:
                            continue
                        key = (email, st)
                        if key in seen:
                            continue
                        seen.add(key)
                        total += 1
                        out.append({'email': email, 'status': st,
                                    'attempts': r.get('attempts'),
                                    'http': r.get('http'), 'ec': r.get('ec'),
                                    'ms': r.get('ms'), 'slot': r.get('slot'),
                                    'device_id': r.get('device_id'),
                                    'device_uses': r.get('device_uses'),
                                    'device_limit': r.get('device_limit'),
                                    'cpu': r.get('thread_cpu_ms'),
                                    'detail': r.get('detail'),
                                    'web_status': r.get('web_status'),
                                    'web_ec': r.get('web_ec'),
                                    'web_detail': r.get('web_detail'),
                                    'web_method': r.get('web_method'),
                                    'web_auth_type': r.get('web_auth_type'),
                                    'web_attempts': r.get('web_attempts'),
                                    'web_proxy_rotations': r.get('web_proxy_rotations'),
                                    'web_rotation_exhausted': r.get('web_rotation_exhausted'),
                                    'web_ms': r.get('web_ms')})
        rows = list(reversed(out))          # 新的在前
        scoped = bool(own and os.path.exists(own)) or bool(cutoff)
        return {'total': total if scoped else 0,
                'rows': rows if scoped else [],
                'status': want, 'query': query, 'scoped': scoped}

    def _export(self, want, fmt):
        """按状态筛选导出账号。只保留 邮箱----密码 两列，不带其他信息。

        同样按 STATE['started'] 限定在本轮任务范围内。
        """
        import glob as _glob
        patterns = [os.path.join(HERE, 'data', 'simple-run.jsonl'),
                    os.path.join(HERE, 'data', 'mp-p*.jsonl')]
        cutoff = STATE.get('started') or 0
        rows, seen = [], set()
        for pat in patterns:
            for path in sorted(_glob.glob(pat)):
                try:
                    if cutoff and os.path.getmtime(path) < cutoff - 5:
                        continue
                except OSError:
                    continue
                try:
                    handle = open(path, encoding='utf-8', errors='replace')
                except OSError:
                    continue
                with handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            r = json.loads(line)
                        except ValueError:
                            continue
                        st = str(r.get('status') or '')
                        if want == 'other':
                            if st not in ('undetermined', 'error', 'need_mac'):
                                continue
                        elif want and want != 'all' and st != want:
                            continue
                        email = str(r.get('email') or '')
                        if not email or email in seen:
                            continue
                        seen.add(email)
                        rows.append(r)
        if fmt == 'csv':
            import csv as _csv, io as _io
            buf = _io.StringIO()
            w = _csv.writer(buf)
            fields = ('email', 'status', 'attempts', 'http', 'ec', 'ms',
                      'slot', 'device_id', 'device_uses', 'device_limit', 'detail')
            w.writerow(fields)
            for r in rows:
                w.writerow([r.get(k, '') for k in fields])
            out = buf.getvalue()
            ctype, name = 'text/csv; charset=utf-8', 'export.csv'
        else:
            src = {}
            acc = STATE['accounts']
            try:
                with open(acc, encoding='utf-8', errors='replace') as handle:
                    for line in handle:
                        line = line.strip()
                        if '----' in line:
                            src[line.split('----', 1)[0]] = line
            except OSError:
                pass
            body = []
            for r in rows:
                em = str(r.get('email') or '')
                line = src.get(em)
                if line:
                    body.append(line)
                elif em:
                    body.append(em)      # 原始文件里没有这行时只导 email
            out = '\n'.join(body) + ('\n' if body else '')
            # 文件名保持 ASCII，筛选参数中的控制字符不得进入响应头。
            safe_status = re.sub(r'[^a-zA-Z0-9_-]', '_', want or 'all')[:80]
            ctype, name = 'text/plain; charset=utf-8', f'export-{safe_status}.txt'
        data = out.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Disposition', f'attachment; filename="{name}"')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        """只接受名称和值均完整匹配的登录 Cookie。"""
        import hmac
        from http.cookies import CookieError, SimpleCookie
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get('Cookie') or '')
        except CookieError:
            return False
        token = cookies.get('gsa_auth')
        return token is not None and hmac.compare_digest(
            token.value.encode('utf-8'), _cookie_token().encode('ascii'))

    def do_POST(self):
        try:
            return self._do_post()
        except Exception as exc:                                   # noqa: BLE001
            import traceback
            err = traceback.format_exc()
            log_path = os.path.join(HERE, 'data', 'web-error.log')
            try:
                os.makedirs(os.path.dirname(log_path), exist_ok=True)
                with open(log_path, 'a', encoding='utf-8') as handle:
                    handle.write(f'--- {time.strftime("%F %T")} POST {self.path}\n{err}\n')
            except OSError:
                pass
            try:
                return self._json({'error': f'后端异常：{type(exc).__name__}: {exc}',
                                   'trace': err.splitlines()[-3:]})
            except Exception:
                pass

    def _do_post(self):
        try:
            length = int(self.headers.get('Content-Length') or 0)
            if length < 0:
                raise ValueError('negative Content-Length')
        except ValueError:
            self.close_connection = True
            return self._json({'error': 'Content-Length 必须是非负整数'})
        if length > 64 * 1024 * 1024:          # 上传上限 64MB
            # 请求体尚未读取，关闭连接以免后续请求误读残留字节。
            self.close_connection = True
            return self._json({'error': '上传内容过大（上限 64MB）'})
        # POST /api/stop has no request body.  Keep the transport body empty
        # while validating Content-Length; substituting ``{}`` before this
        # check made a valid zero-byte request look like an interrupted upload
        # (expected 0 bytes, received 2 bytes).
        raw = self.rfile.read(length) if length else b''
        if len(raw) != length:
            return self._json({'error':
                f'上传中断：应收到 {length} 字节，实际收到 {len(raw)} 字节，请重试'})

        # 文件上传直接发送原始字节，避免浏览器先把大文件读成字符串、再做一遍
        # JSON 转义和复制。保留下面的 JSON 分支以兼容旧页面。
        content_type = (self.headers.get('Content-Type') or '').lower()
        if self.path.startswith('/api/upload') and \
                'application/octet-stream' in content_type:
            if not self._authorized():
                return self._json({'error': '请先输入密码', 'need_login': True})
            from urllib.parse import urlparse, parse_qs
            query = parse_qs(urlparse(self.path).query)
            name = (query.get('name') or ['accounts.txt'])[0]
            if 'gzip' in (self.headers.get('Content-Encoding') or '').lower():
                try:
                    raw = gzip.decompress(raw)
                except (OSError, EOFError):
                    return self._json({'error': '压缩文件损坏，请重新选择文件上传'})
                if len(raw) > 64 * 1024 * 1024:
                    return self._json({'error': '解压后内容过大（上限 64MB）'})
            try:
                content = raw.decode('utf-8-sig')
            except UnicodeDecodeError:
                return self._json({'error': '文件不是 UTF-8 文本，请转换编码后重试'})
            return self._json(self._upload({'name': name, 'content': content}))

        try:
            payload = json.loads((raw or b'{}').decode('utf-8'))
        except ValueError:
            return self._json({'error': '请求体不是合法 JSON'})
        if not isinstance(payload, dict):
            return self._json({'error': '请求体必须是 JSON 对象'})
        if not self.path.startswith('/api/login') and not self._authorized():
            return self._json({'error': '请先输入密码', 'need_login': True})

        if self.path.startswith('/api/set-api'):
            raw = str(payload.get('api') or '')
            if not raw.strip():
                return self._json({'error': '接口地址不能为空'})
            if re.search(r'(?i)(?:password|passwd|pwd|token|key)=\*{3}(?:&|$)', raw):
                return self._json({'error': '这是页面隐藏后的地址，不会覆盖真实密码；'
                                          '请粘贴供应商给的完整接口'})
            fixed = normalize_api(raw)
            if '{num}' not in fixed:
                return self._json({'error': '无法识别 num 参数，请确认地址里有 num=数字'})
            try:
                validate_proxy_api(fixed)
                save_api(fixed)
            except (OSError, ValueError) as exc:
                return self._json({'error': f'保存接口失败: {exc}'})
            return self._json({'ok': True, 'api': mask_api(fixed)})
        if self.path.startswith('/api/login'):
            if str(payload.get('password') or '') != PASSWORD:
                return self._json({'error': '密码不对'})
            body = json.dumps({'ok': True}).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Set-Cookie',
                             f'gsa_auth={_cookie_token()}; Path=/; Max-Age=604800; HttpOnly')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if not self._authorized():
            return self._json({'error': '请先输入密码', 'need_login': True})
        if self.path.startswith('/api/upload'):
            return self._json(self._upload(payload))
        if self.path.startswith('/api/start'):
            with _LOCK:
                result = start_job(payload.get('accounts') or STATE['accounts'],
                                   payload.get('threads') or 100,
                                   payload.get('limit') or 0,
                                   payload.get('processes') or 1,
                                   bool(payload.get('verify_web')),
                                   int(payload.get('per_ip') or 6),
                                   float(payload.get('ip_ttl') or 50),
                                   float(payload.get('timeout') or 25),
                                   int(payload.get('anisette_workers') or 0),
                                   bool(payload.get('no_register')),
                                   int(payload.get('retry') if payload.get('retry') is not None else 2),
                                   float(payload.get('item_timeout') or 40),
                                   bool(payload.get('anisette_proxy')),
                                   int(payload.get('device_max_uses')
                                       if payload.get('device_max_uses') is not None else 100),
                                   float(payload.get('anisette_timeout') or 20))
            return self._json(result)
        if self.path.startswith('/api/stop'):
            with _LOCK:
                return self._json(stop_job())
        if self.path.startswith('/api/clear-devices'):
            with _LOCK:
                return self._json(clear_devices())
        return self._json({'error': 'unknown endpoint'})

    def _upload(self, payload):
        name = os.path.basename(str(payload.get('name') or 'accounts.txt'))
        content = payload.get('content')
        if not isinstance(content, str) or not content.strip():
            return {'error': '文件内容为空'}
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        safe = ''.join(c for c in name if c.isalnum() or c in '._-') or 'accounts.txt'
        path = os.path.join(UPLOAD_DIR, f'{int(time.time())}-{safe}')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(content)
        # 不改 STATE['accounts']：正在跑的任务还在用旧文件，页面不能把新文件显示成当前
        STATE['pending_accounts'] = path
        STATE['take_pending'] = True
        _remember_accounts(path)
        _ACCOUNT_CACHE.clear()
        info = analyse_accounts(path)
        info['uploaded'] = True
        return info

    def log_message(self, *args):
        pass


def tail_log(lines=4, window=65536):
    """只读文件末尾一段，不整文件扫描（16 MiB 日志全扫一次约 32ms）。"""
    try:
        with open(STATE['log'], 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - window))
            chunk = handle.read().decode('utf-8', errors='replace')
    except OSError:
        return []
    rows = [r.rstrip() for r in chunk.splitlines()
            if r.strip() and 'Warning' not in r and 'warnings.warn' not in r]
    return rows[-lines:] if size > window else rows[-lines:]


PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GSA 校验控制台</title>
<style>
:root{--bg:#f5f7fa;--card:#fff;--line:#e5e7eb;--fg:#111827;--dim:#6b7280;
--blue:#2563eb;--green:#16a34a;--amber:#d97706;--red:#dc2626;--gray:#9ca3af}
*{box-sizing:border-box}
html,body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",
"Hiragino Sans GB","Microsoft YaHei",Arial,sans-serif}
body{margin:0;background:var(--bg);color:var(--fg);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",
"Hiragino Sans GB","Microsoft YaHei",Arial,sans-serif;
font-size:14px;line-height:1.55;
-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
a{color:var(--blue);text-decoration:none}
.top{background:#fff;border-bottom:1px solid var(--line);padding:14px 24px;
display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:20;flex-wrap:wrap}
.top h1{font-size:17px;margin:0;font-weight:700}
.tag{background:#eef2ff;color:#4338ca;font-size:11px;padding:2px 8px;border-radius:6px}
.top .right{margin-left:auto;display:flex;align-items:center;gap:14px;font-size:12px;
color:var(--dim);min-width:0;flex-wrap:wrap}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:middle}

.layout{display:grid;grid-template-columns:minmax(280px,330px) minmax(0,1fr);
gap:16px;padding:16px 24px;align-items:start;width:100%;max-width:100vw}
.layout>*{min-width:0}.layout{overflow:hidden}
@media(max-width:1080px){.layout{grid-template-columns:1fr}}

.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;
min-width:0;overflow:hidden}
.panel>.hd{padding:14px 16px;border-bottom:1px solid var(--line);display:flex;
align-items:center;justify-content:space-between;min-width:0;gap:10px;flex-wrap:wrap}
.panel>.hd>span{min-width:0;max-width:100%;display:flex;gap:8px;flex-wrap:wrap}
.panel>.hd b{font-size:14px}
.panel>.bd{padding:16px;min-width:0}

.field{margin-bottom:14px}
.field>label{display:block;font-size:12px;color:var(--dim);margin-bottom:6px}
.field>label b{color:var(--fg);font-weight:600}
input[type=number],input[type=password],input[type=text],select{font-family:inherit;
width:100%;border:1px solid var(--line);border-radius:8px;padding:8px 10px;
font-size:13px;background:#fff;color:var(--fg);font-variant-numeric:tabular-nums}
input:focus,select:focus{outline:2px solid #bfdbfe;border-color:var(--blue)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.drop{border:1.5px dashed var(--line);border-radius:8px;padding:16px;text-align:center;
color:var(--dim);font-size:12px;cursor:pointer;transition:.15s}
.drop:hover,.drop.on{border-color:var(--blue);background:#f8fbff;color:var(--blue)}
.btn{border:0;border-radius:8px;padding:10px 18px;font-size:13px;font-weight:600;
cursor:pointer;transition:.15s}
.btn.primary{background:var(--green);color:#fff}
.btn.primary:hover{background:#15803d}
.btn.danger{background:var(--red);color:#fff}
.btn.danger:hover{background:#b91c1c}
.btn.ghost{background:#fff;border:1px solid var(--line);color:var(--fg)}
.btn.danger-outline{background:#fff;border:1px solid #fecaca;color:#b91c1c;
padding:6px 10px;font-size:11.5px;white-space:nowrap}
.btn.danger-outline:hover{background:#fef2f2;border-color:#fca5a5}
.btn:disabled{opacity:.45;cursor:not-allowed}
.task-actions{display:grid;grid-template-columns:minmax(0,1fr) 72px 72px;gap:10px}
.task-actions .btn{padding:10px 12px;white-space:nowrap}
.device-maintenance{margin-top:10px;padding:8px 10px;border:1px solid var(--line);
border-radius:8px;background:#fafbfc;display:flex;align-items:center;
justify-content:space-between;gap:10px}
.device-maintenance .title{font-size:11.5px;font-weight:600;color:#374151}
.device-maintenance .desc{font-size:10.5px;color:var(--dim);margin-left:6px}
.chk{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--fg)}
.hint{font-size:11px;color:var(--dim);line-height:1.5;margin-top:5px}

.stats{display:grid;grid-template-columns:repeat(11,minmax(0,1fr));gap:0;
background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
@media(max-width:1500px){.stats{grid-template-columns:repeat(6,minmax(0,1fr))}}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
.stat{padding:12px 14px;border-right:1px solid var(--line)}
.stat:last-child{border-right:0}
.stat .k{font-size:11px;color:var(--dim);margin-bottom:4px;white-space:nowrap}
.stat .v{font-size:23px;font-weight:700;letter-spacing:-.3px;
font-family:inherit;font-variant-numeric:tabular-nums;
font-feature-settings:"tnum" 1,"lnum" 1}
.stat .v.sm{font-size:17px}
.v-green{color:var(--green)}.v-red{color:var(--red)}.v-amber{color:var(--amber)}
.v-blue{color:var(--blue)}.v-gray{color:var(--gray)}

.prog{margin-top:12px}
.prog .bar{height:8px;background:#eef1f5;border-radius:6px;overflow:hidden}
.prog .bar>i{display:block;height:100%;width:0;background:var(--blue);transition:width .4s}
.prog .meta{display:flex;justify-content:space-between;font-size:12px;color:var(--dim);
margin-top:7px;font-family:inherit;font-variant-numeric:tabular-nums}
.startup{display:none;margin-bottom:12px;padding:10px 12px;border:1px solid #bfdbfe;
background:#eff6ff;border-radius:8px;color:#1e3a8a;font-size:12px;line-height:1.7}
.startup.show{display:block}.startup b{font-size:13px}.startup .items{display:flex;
gap:18px;flex-wrap:wrap;color:#475569;margin-top:3px}

.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl th{text-align:left;padding:9px 12px;color:var(--dim);font-weight:500;
font-size:11.5px;border-bottom:1px solid var(--line);background:#fafbfc;white-space:nowrap}
.tbl td{padding:9px 12px;border-bottom:1px solid #f3f4f6;white-space:nowrap;
font-family:inherit;font-variant-numeric:tabular-nums;
font-feature-settings:"tnum" 1,"lnum" 1}
.tbl tr:hover td{background:#fafbfc}
.badge{display:inline-block;padding:1.5px 8px;border-radius:5px;font-size:11px;font-weight:600}
.b-green{background:#dcfce7;color:#166534}
.b-red{background:#fee2e2;color:#991b1b}
.b-amber{background:#fef3c7;color:#92400e}
.b-gray{background:#f3f4f6;color:#4b5563}
.b-blue{background:#dbeafe;color:#1e40af}
.scroll{max-height:520px;max-width:100%;overflow:auto}
.mono,.stat .v,.tbl td,.tbl th{font-family:inherit;
font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1,"lnum" 1}
#gate{position:fixed;inset:0;background:rgba(17,24,39,.55);z-index:99;display:none;
align-items:center;justify-content:center;backdrop-filter:blur(2px)}
#gate .panel{width:330px}
</style></head><body>

<div class="top">
  <h1>GSA 校验控制台</h1>
  <span class="tag">极简模型</span>
  <span class="tag" id="versionTag">v__APP_VERSION__</span>
  <div class="right">
    <span id="stateTag"><span class="dot" style="background:#9ca3af"></span>未开始</span>
    <span><span id="runtimeLabel">已运行</span> <b id="runtime">--:--:--</b></span>
    <span>SRP <b id="backend">--</b></span>
    <a href="#" id="logout">换个密码</a>
  </div>
</div>

<div class="layout">
  <!-- 左：任务设置 -->
  <div class="panel">
    <div class="hd"><b>任务设置</b><span class="tag" id="modeTag">单进程</span></div>
    <div class="bd">
      <div class="field">
        <label>代理接口 <b id="apiState">未配置</b></label>
        <input type="text" id="api" placeholder="粘贴接口地址，num=1 会自动变成 {num}">
        <div style="display:flex;gap:8px;margin-top:6px">
          <button class="btn ghost" id="saveApi" style="flex:1">保存接口</button>
        </div>
        <div class="hint" id="apiHint">程序会按需要的数量自动替换 num</div>
      </div>

      <div class="field">
        <label>账号文件 <b id="accName">未选择</b></label>
        <div class="drop" id="drop">点击或拖入 .txt（账号----密码）</div>
        <input type="file" id="file" accept=".txt,.csv" style="display:none">
        <div class="hint" id="accInfo"></div>
      </div>

      <div class="field">
        <label>并发</label>
        <div class="row2">
          <div><input type="number" id="processes" value="4" min="1" max="8" placeholder="进程数">
            <div class="hint">进程数</div></div>
          <div><input type="number" id="threads" value="1000" min="1" max="2000" placeholder="线程/进程">
            <div class="hint">每进程线程</div></div>
        </div>
        <div class="hint" id="rechint"></div>
      </div>

      <div class="field">
        <label>条数（0 = 全部）</label>
        <input type="number" id="limit" value="0" min="0">
      </div>

      <div class="field">
        <label>代理参数</label>
        <div class="row2" style="margin-bottom:10px">
          <div><input type="number" id="perip" value="6" min="1" max="50">
            <div class="hint">每 IP 条数</div></div>
          <div><input type="number" id="ttl" value="50" min="10" max="600" step="5">
            <div class="hint">IP 有效期/秒</div></div>
        </div>
        <div class="row2">
          <div><input type="number" id="otpreuse" value="15" min="0" max="50">
            <div class="hint">公共头复用次数</div></div>
          <div><input type="number" id="anito" value="20" min="3" max="60">
            <div class="hint">公共头超时/秒（线程独立重取）</div></div>
        </div>
        <div class="row2" style="margin-top:10px">
          <div><input type="number" id="timeout" value="25" min="3" max="60">
            <div class="hint">业务请求超时/秒</div></div>
          <div><input type="number" id="retry" value="2" min="0" max="5">
            <div class="hint">重试次数</div></div>
        </div>
        <div style="margin-top:10px">
          <div><input type="number" id="itemto" value="40" min="5" max="120" step="5">
            <div class="hint">单条超时/秒</div></div>
        </div>
        <div class="hint" style="margin-top:4px">
          单条超时 = 这条账号的总预算（含所有重试），超了直接判超时，不再磕
        </div>
        <div style="margin-top:10px">
          <input type="number" id="deviceMaxUses" value="100" min="0" max="100000">
          <div class="hint">设备使用上限（完成 100 条后自动销毁并换新；0 = 不限）</div>
        </div>
      </div>

      <div class="field">
        <label class="chk"><input type="checkbox" id="vweb"> GSA 判 au=repair 时用 web 复核</label>
        <label class="chk" style="margin-top:8px"><input type="checkbox" id="noreg"> 跳过设备注册检查</label>
        <label class="chk" style="margin-top:8px"><input type="checkbox" id="asproxy"> 公共头走代理 <span style="color:var(--amber);font-size:11px">（机房 IP 直连 sidestore 超时时勾）</span></label>
      </div>

      <div class="task-actions">
        <button class="btn primary" id="start">开始</button>
        <button class="btn danger" id="stop" disabled>停止</button>
        <button class="btn ghost" id="refresh">刷新</button>
      </div>
      <div class="device-maintenance">
        <span><span class="title">设备池维护</span><span class="desc">任务停止后可用</span></span>
        <button class="btn danger-outline" id="clearDevices">清空设备</button>
      </div>
      <div class="hint" id="hint" style="margin-top:10px"></div>
    </div>
  </div>

  <!-- 右：进度与结果 -->
  <div>
    <div class="panel" style="margin-bottom:16px">
      <div class="hd"><b>进度与结果</b><span class="hint" id="modeHint">本地执行</span></div>
      <div class="bd" style="padding-bottom:0">
        <div class="startup" id="startupPanel">
          <b id="mStartupPhase">正在初始化</b>
          <div class="items">
            <span id="mStartupProxy">代理 IP：等待拉取</span>
            <span id="mStartupDevices">设备：等待读取</span>
            <span id="mStartupHeaders">公共头：等待工作线程</span>
            <span id="mStartupProcesses">进程：等待启动</span>
          </div>
        </div>
        <div class="stats">
          <div class="stat"><div class="k">总数</div><div class="v" id="sTotal">0</div></div>
          <div class="stat"><div class="k">完成</div><div class="v v-blue" id="sDone">0</div></div>
          <div class="stat"><div class="k">剩余</div><div class="v" id="sLeft">0</div></div>
          <div class="stat"><div class="k">当前速度</div><div class="v sm v-green" id="sRate">0</div></div>
          <div class="stat"><div class="k">密码正确</div><div class="v v-green" id="sValid">0</div></div>
          <div class="stat"><div class="k">密码错误</div><div class="v v-red" id="sWrong">0</div></div>
          <div class="stat"><div class="k">锁定</div><div class="v v-amber" id="sLock">0</div></div>
          <div class="stat"><div class="k">双重验证</div><div class="v" id="s2fa">0</div></div>
          <div class="stat"><div class="k">不存在</div><div class="v" id="sNF">0</div></div>
          <div class="stat"><div class="k">超时</div><div class="v v-gray" id="sTO">0</div></div>
          <div class="stat"><div class="k">其他</div><div class="v v-gray" id="sOther">0</div></div>
        </div>

        <div class="prog">
          <div class="bar"><i id="bar"></i></div>
          <div class="meta">
            <span><b id="pText">0 / 0</b> <span id="pPct">0%</span></span>
            <span id="pSpeed">-- 条/小时</span>
          </div>
        </div>

        <div class="meta" style="display:flex;justify-content:space-between;
             padding:12px 0;border-top:1px solid var(--line);margin-top:12px;font-size:12px;color:var(--dim)">
          <span id="mThreads">-- 线程</span>
          <span id="mCpu">CPU -- 核</span>
          <span id="mP50">p50 -- ms</span>
          <span id="mOtp">公共头 命中 -- / 拉取 --</span>
          <span id="mRetry">重试 --</span>
          <span id="mEta">--</span>
        </div>
        <div class="meta" style="display:flex;justify-content:space-between;
             padding:10px 0 2px;border-top:1px solid var(--line);font-size:12px;color:var(--dim)">
          <span id="mDevices">设备池 已注册 -- / 使用中 -- / 注册中 --</span>
          <span id="mIpPool">IP池 库存 -- / 低水位 -- / 目标 --</span>
          <span id="mRegErr">注册换代理 --</span>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="hd"><b>最近结果</b>
        <span style="display:flex;gap:8px;align-items:center">
          <input id="resultSearch" type="search" placeholder="搜索账号"
            autocomplete="off" style="width:180px;padding:5px 9px;font-size:12px">
          <select id="filter" style="width:auto;padding:5px 9px;font-size:12px">
            <option value="all">全部结果</option>
            <option value="valid">密码正确</option>
            <option value="wrong_password">密码错误</option>
            <option value="locked">锁定</option>
            <option value="need_2fa">双重验证</option>
            <option value="not_found">不存在</option>
            <option value="timeout">超时</option>
            <option value="other">其他（未归类 + 错误）</option>
          </select>
          <button class="btn ghost" id="expTxt" style="padding:5px 12px;font-size:12px">导出账号</button>
          <button class="btn ghost" id="expCsv" style="padding:5px 12px;font-size:12px">导出明细</button>
          <span class="hint" id="tblHint">实时刷新</span>
        </span>
      </div>
      <div class="scroll">
        <table class="tbl">
          <thead><tr>
            <th style="width:52px">#</th><th>账号</th><th style="width:110px">状态</th>
            <th style="width:80px">耗时（秒）</th><th style="width:80px">CPU</th>
            <th style="width:60px">设备</th><th style="width:82px">设备ID</th>
            <th style="width:72px">使用</th><th style="width:70px">HTTP</th>
            <th style="width:80px">业务码</th><th style="width:190px">Web复核</th>
            <th>原因（Apple 原文）</th>
          </tr></thead>
          <tbody id="rows"><tr><td colspan="12" style="text-align:center;color:#9ca3af;padding:24px">
            还没有结果</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<div id="gate"><div class="panel">
  <div class="hd"><b>输入控制台密码</b></div>
  <div class="bd">
    <input type="password" id="pwd" placeholder="密码">
    <button class="btn primary" id="login" style="width:100%;margin-top:10px">进入</button>
    <div class="hint" id="pwerr" style="color:var(--red)"></div>
  </div>
</div></div>

<script>
const $ = id => document.getElementById(id);
const num = n => (n ?? 0).toLocaleString();
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({
  '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
}[ch]));
const cls = s => !s ? 'b-gray'
  : ['valid'].includes(s) ? 'b-green'
  : ['wrong_password','not_found'].includes(s) ? 'b-red'
  : ['locked','security_lock','need_2fa','need_mac'].includes(s) ? 'b-amber'
  : ['timeout'].includes(s) ? 'b-gray' : 'b-blue';
const statusLabel = s => ({valid:'密码正确'})[s] || s;
const webStatusLabel = s => ({
  valid:'密码正确',
  security_lock:'锁定', wrong_password:'密码错误', not_found:'不存在',
  need_2fa:'双重验证', needs_setup:'安全设置',
  web_unavailable:'复核不可用', web_timeout:'复核超时', web_error:'复核异常'
})[s] || s;
const webMethodLabel = s => ({
  verification_code:'验证码', security_repair:'安全修复',
  repair_unspecified:'仍无法细分'
})[s] || s;

function webReviewHtml(r){
  if(r.web_status){
    const parts = [webStatusLabel(r.web_status)];
    if(r.web_method) parts.push(webMethodLabel(r.web_method));
    if(r.web_auth_type) parts.push(`authType=${r.web_auth_type}`);
    if(Number(r.web_proxy_rotations||0)>0) parts.push(`换IP ${r.web_proxy_rotations}`);
    if(r.web_rotation_exhausted) parts.push('无可用新IP');
    if(r.web_ec != null) parts.push(`EC ${r.web_ec}`);
    if(r.web_ms) parts.push(`${(Number(r.web_ms)/1000).toFixed(2)}s`);
    const detail = String(r.web_detail||'');
    return `<span class="badge ${cls(r.web_status)}" title="${esc(detail)}">${esc(parts.join(' · '))}</span>`;
  }
  if((r.status||'') === 'need_2fa'){
    return `<span style="color:#9ca3af" title="仅 au=repair 需要 Web 复核">无需复核</span>`;
  }
  return '<span style="color:#d1d5db">--</span>';
}

let shownAccounts = null;

/* ---- 登录 ---- */
async function login(){
  const res = await (await fetch('/api/login',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({password:$('pwd').value})})).json();
  if(res.error){ $('pwerr').textContent = res.error; return; }
  $('gate').style.display='none'; loadAccounts(); tick();
}
$('login').onclick = login;
$('pwd').addEventListener('keydown', e => { if(e.key==='Enter') login(); });
$('logout').onclick = e => { e.preventDefault(); document.cookie='gsa_auth=; Max-Age=0; path=/'; location.reload(); };

/* ---- 代理接口 ---- */
async function loadApi(){
  try{
    const r = await (await fetch('/api/api-config')).json();
    // The masked URL is display-only.  Never put password=*** back into the
    // editable value because a second Save would destroy the real credential.
    $('api').value = '';
    if(r.api) $('api').placeholder = '已配置：' + r.api + '（要更换请粘贴完整新接口）';
    $('apiState').textContent = r.configured ? '已配置' : '未配置';
    $('apiState').style.color = r.configured ? 'var(--green)' : 'var(--red)';
  }catch(e){}
}
async function saveApiFn(){
  const url = $('api').value.trim();
  if(!url){ $('apiHint').textContent='先粘贴接口地址'; return; }
  const r = await (await fetch('/api/set-api',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({api:url})})).json();
  if(r.error){ $('apiHint').textContent = r.error; $('apiHint').style.color='var(--red)'; }
  else { $('apiHint').textContent = '已保存：' + r.api;
         $('apiHint').style.color='var(--green)';
         $('api').value = '';
         $('api').placeholder = '已配置：' + r.api + '（要更换请粘贴完整新接口）';
         $('apiState').textContent='已配置';
         $('apiState').style.color='var(--green)'; }
}
$('saveApi').onclick = saveApiFn;
loadApi();

/* ---- 上传 ---- */
const fileInput = $('file');
$('drop').onclick = () => {
  // 先清空，否则重复选同一个文件时浏览器不会再触发 change。
  fileInput.value = '';
  fileInput.click();
};
fileInput.addEventListener('change', async e => {
  const file = e.target.files && e.target.files[0];
  if(!file) return;
  await upload(file);
  // 上传完继续清空，下次仍可选同名文件。
  e.target.value = '';
});
['dragenter','dragover'].forEach(k=>$('drop').addEventListener(k,e=>{
  e.preventDefault(); $('drop').classList.add('on');}));
['dragleave','drop'].forEach(k=>$('drop').addEventListener(k,e=>{
  e.preventDefault(); $('drop').classList.remove('on');}));
$('drop').addEventListener('drop', e => {
  if(e.dataTransfer.files[0]) upload(e.dataTransfer.files[0]); });

async function upload(file){
  const status = $('accInfo');
  $('accName').textContent = file.name;
  status.textContent = `正在读取 ${file.name}…`;
  status.style.color = 'var(--dim)';
  try{
    let body = file;
    const headers = {'Content-Type':'application/octet-stream'};
    if('CompressionStream' in window){
      status.textContent = `正在压缩 ${file.name}…`;
      body = await new Response(
        file.stream().pipeThrough(new CompressionStream('gzip'))).blob();
      headers['Content-Encoding'] = 'gzip';
    }
    const fromSize = (file.size/1048576).toFixed(1);
    const toSize = (body.size/1048576).toFixed(1);
    status.textContent = body === file
      ? `正在上传 ${file.name}（${fromSize} MB）…`
      : `正在上传 ${file.name}（${fromSize} → ${toSize} MB）…`;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 600000);
    let response;
    try{
      response = await fetch('/api/upload?name='+encodeURIComponent(file.name),{
        method:'POST',
        headers,
        body,
        signal:ctl.signal});
    }finally{
      clearTimeout(timer);
    }
    const text = await response.text();
    let res;
    try{ res = JSON.parse(text); }
    catch(e){ throw new Error(`服务返回 HTTP ${response.status}：${text.slice(0,120)}`); }
    if(!response.ok || res.error) throw new Error(res.error || `HTTP ${response.status}`);
    renderAccounts(res);
    status.style.color = 'var(--green)';
    $('hint').textContent = `已上传 ${res.name}：${num(res.total)} 条`;
    $('hint').style.color = 'var(--green)';
  }catch(e){
    const msg = e && e.name === 'AbortError' ? '上传超过 10 分钟，请检查网络后重试'
      : (e.message || e);
    status.textContent = `上传失败：${msg}`;
    status.style.color = 'var(--red)';
    $('hint').textContent = status.textContent;
    $('hint').style.color = 'var(--red)';
  }
}

function renderAccounts(a){
  if(!a || a.error){ $('accInfo').textContent = a ? a.error : ''; return; }
  $('accName').textContent = a.name || '';
  $('accInfo').textContent =
    `${num(a.total)} 条 · ${a.top_domains?.[0]?.[0]||'--'} · 密码=用户名 ${a.password_equals_ratio}%`
    + (a.format_error ? ` · 格式异常 ${a.format_error}` : '');
}

/* ---- 启停 ---- */
async function post(url, body){
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 30000);
  try{
    const r = await fetch(url, {method:'POST', signal:ctl.signal,
      headers:{'Content-Type':'application/json'},
      body: body ? JSON.stringify(body) : undefined});
    const text = await r.text();
    if(!r.ok){
      if(r.status === 401 || r.status === 403) return {error:'请重新输入密码'};
      return {error:`服务返回 HTTP ${r.status}：${text.slice(0,160)}`};
    }
    try{ return JSON.parse(text); }
    catch(e){ return {error:`返回不是 JSON：${text.slice(0,160)}`}; }
  }catch(e){
    return {error: e.name === 'AbortError'
      ? '请求超时 30 秒（服务器没响应）'
      : `请求失败：${e.message}`};
  }finally{ clearTimeout(timer); }
}

async function start(){
  const body = {threads:+$('threads').value, limit:+$('limit').value,
    processes:+$('processes').value, verify_web:$('vweb').checked,
    per_ip:+$('perip').value, ip_ttl:+$('ttl').value,
    timeout:+$('timeout').value, anisette_timeout:+$('anito').value,
    no_register:$('noreg').checked,
    retry:+$('retry').value, item_timeout:+$('itemto').value,
    anisette_proxy:$('asproxy').checked,
    device_max_uses:+$('deviceMaxUses').value};
  $('start').disabled = true; $('hint').textContent='启动中…';
  $('hint').style.color = 'var(--dim)';
  const res = await post('/api/start', body);
  if(res.error){
    $('hint').textContent = '✕ ' + res.error;
    $('hint').style.color = 'var(--red)';
    $('start').disabled = false;
  }else{
    resetResultsForNewTask(res.total);
    $('hint').textContent = res.warmup_hint || '已启动';
    $('hint').style.color = 'var(--green)';
  }
}
function resetResultsForNewTask(total){
  HIST = null;
  $('filter').value = 'all';
  $('resultSearch').value = '';
  $('tblHint').textContent = '实时刷新';
  LAST = {running:true, finished:false, total:Number(total)||0, done:0, recent:[]};
  renderRows();
}
async function stop(){
  $('stop').disabled = true;
  $('hint').textContent = '正在停止…';
  $('hint').style.color = 'var(--dim)';
  const res = await post('/api/stop');
  $('hint').textContent = res.error ? ('✕ ' + res.error) : '已停止';
  $('hint').style.color = res.error ? 'var(--red)' : 'var(--dim)';
  await tick();
}
async function clearDevices(){
  if(!window.confirm('确定清空所有已注册设备？清空后下次任务需要重新注册。')) return;
  const button = $('clearDevices');
  button.disabled = true;
  $('hint').textContent = '正在清空设备…';
  $('hint').style.color = 'var(--dim)';
  const res = await post('/api/clear-devices');
  if(res.error){
    $('hint').textContent = '✕ ' + res.error;
    $('hint').style.color = 'var(--red)';
  }else{
    $('hint').textContent = `已清空 ${num(res.cleared)} 个已注册设备`;
    $('hint').style.color = 'var(--green)';
  }
  button.disabled = false;
  await tick();
}
$('start').onclick = start;
$('stop').onclick = stop;
$('refresh').onclick = () => { shownAccounts=null; tick(); };
$('clearDevices').onclick = clearDevices;

/* ---- 推荐提示 ---- */
function refreshHint(){
  const p=+$('processes').value, t=+$('threads').value, total=p*t, warn=[];
  if(p===1 && t>1600) warn.push('单进程超 1600 线程会放大上游长尾');
  if(total>4000) warn.push(`总线程 ${total} 可能放大代理排队`);
  if(p>1 && t>1600) warn.push('每进程超 1600 线程边际递减');
  $('rechint').textContent = warn.length ? '⚠ '+warn.join('；')
    : `共 ${total} 线程 · 同步 HTTP · 线程模式`;
  $('rechint').style.color = warn.length ? 'var(--amber)' : 'var(--dim)';
  $('modeTag').textContent = p>1 ? `${p} 进程` : '单进程';
  $('rechint').style.color = warn.length ? 'var(--amber)' : 'var(--dim)';
}
['processes','threads'].forEach(id=>$(id).addEventListener('input', refreshHint));
refreshHint();

/* ---- 导出 ---- */
function exportAs(fmt){
  const st = $('filter').value;
  const url = `/api/export?status=${encodeURIComponent(st)}&fmt=${fmt}`;
  const a = document.createElement('a');
  a.href = url; a.download = '';
  document.body.appendChild(a); a.click(); a.remove();
  $('tblHint').textContent = '已导出';
  setTimeout(()=>{ $('tblHint').textContent = '实时刷新'; }, 2000);
}
$('expTxt').onclick = () => exportAs('txt');
$('expCsv').onclick = () => exportAs('csv');
$('filter').onchange = () => {
  const want = $('filter').value;
  const query = $('resultSearch').value.trim();
  if((want && want !== 'all') || query){ loadHistory(want); }
  else { HIST = null; $('tblHint').textContent = '实时刷新'; renderRows(); }
};
let SEARCH_TIMER = null;
$('resultSearch').oninput = () => {
  clearTimeout(SEARCH_TIMER);
  SEARCH_TIMER = setTimeout(() => {
    const want = $('filter').value;
    const query = $('resultSearch').value.trim();
    if(query || (want && want !== 'all')) loadHistory(want);
    else { HIST = null; $('tblHint').textContent = '实时刷新'; renderRows(); }
  }, 250);
};

/* ---- 主循环 ---- */
function setStat(id, v){ $(id).textContent = num(v); }

async function tick(){
  if(TICK_RUNNING) return;
  TICK_RUNNING = true;
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(), 4000);
  let d;
  try{ d = await (await fetch('/api/live?t='+Date.now(), {signal:controller.signal})).json(); }
  catch(e){ $('stateTag').innerHTML='<span class="dot" style="background:#dc2626"></span>读取失败'; return; }
  finally{ clearTimeout(timeout); TICK_RUNNING = false; }
  if(d.error){
    if(d.need_login){ $('gate').style.display='flex'; $('pwd').focus(); return; }
    $('stateTag').innerHTML='<span class="dot" style="background:#9ca3af"></span>'+esc(d.error);
    return;
  }
  const by = d.by_status || {};
  const done = Number(d.done) || 0;
  const total = Math.max(Number(d.total) || 0, done);
  setStat('sTotal', total); setStat('sDone', done);
  setStat('sLeft', Math.max(0, total-done));
  $('sRate').textContent = (d.rate||0).toFixed(1);
  setStat('sValid', by.valid);
  setStat('sWrong', by.wrong_password); setStat('sLock', by.locked);
  setStat('s2fa', by.need_2fa); setStat('sNF', by.not_found);
  setStat('sTO', by.timeout);
  setStat('sOther', (by.undetermined||0)+(by.error||0)+(by.need_mac||0));

  const pct = total ? done/total*100 : 0;
  $('bar').style.width = pct.toFixed(1)+'%';
  $('pText').textContent = `${num(done)} / ${num(total)}`;
  $('pPct').textContent = pct.toFixed(1)+'%';
  $('pSpeed').textContent = `${num(d.per_hour)} 条/小时`;

  const elapsed = Math.max(0, Math.floor(Number(d.elapsed)||0));
  const hh = String(Math.floor(elapsed/3600)).padStart(2,'0');
  const mm = String(Math.floor(elapsed%3600/60)).padStart(2,'0');
  const ss = String(elapsed%60).padStart(2,'0');
  $('runtimeLabel').textContent = d.running ? '已运行' : (d.finished ? '本次用时' : '已运行');
  $('runtime').textContent = `${hh}:${mm}:${ss}`;
  $('runtime').title = d.started ? `启动 ${d.started}` : '';
  $('backend').textContent = [d.backend, d.engine].filter(Boolean).join('·') || '--';
  $('backend').style.color = d.backend==='gmpy2' ? 'var(--green)' : 'var(--red)';
  const threads = Number(d.threads) || Number($('threads').value) || 0;
  const processes = Number(d.processes) || Number($('processes').value) || 1;
  $('mThreads').textContent = processes>1
    ? `${threads} 线程 × ${processes} 进程` : `${threads} 线程`;
  const procCores = d.proc_cpu_cores ?? d.cpu_cores ?? 0;
  const nowCores = d.proc_cpu_now;
  $('mCpu').textContent = nowCores == null
    ? `CPU 平均 ${procCores.toFixed(2)} 核`
    : `CPU 当前 ${Number(nowCores).toFixed(2)} 核 · 平均 ${procCores.toFixed(2)} 核`
    + (d.cpu_per_account ? ` · ${d.cpu_per_account.toFixed(1)} ms/条` : '');
  $('mP50').textContent = `p50 ${d.p50 ?? '--'} ms · p90 ${d.p90 ?? '--'} ms`;
  $('mOtp').textContent = `公共头 命中 ${num(d.otp_hit)} / 拉取 ${num(d.otp_fetch)}`;
  const rk = d.by_retry || {};
  const rkText = Object.keys(rk).length
    ? ' · ' + Object.entries(rk).map(([k,v]) => `${k}:${v}`).join(' ') : '';
  $('mRetry').textContent = `重试 ${num(d.retried)}${rkText}`;
  $('mDevices').textContent = d.running
    ? `设备池 已注册 ${num(d.device_registered ?? d.device_ready)} / 使用中 ${num(d.device_in_use)} / 注册中 ${num(d.device_registering)}`
    : `设备池 总设备 ${num(d.device_total ?? d.device_registered ?? d.device_ready)} / 当前空闲`;
  const pool = d.ip_pool || {};
  const startup = d.startup || {};
  const startupLabels = {
    device_scan:'扫描设备', device_load:'读取设备', spawning:'启动进程',
    proxy_fetch:'拉取代理', device_register:'注册设备', public_header:'获取公共头', ready:'准备就绪',
    running:'业务校验', complete:'任务完成', stopped:'任务停止'
  };
  const startupActive = Boolean(d.running && done === 0 && startup.phase);
  $('startupPanel').classList.toggle('show', startupActive);
  $('mStartupPhase').textContent = `${startupLabels[startup.phase] || '正在初始化'} · ${startup.message || ''}`;
  $('mStartupProxy').textContent = `代理 IP：已拉取 ${num(startup.proxy_fetched)} / 目标 ${num(startup.proxy_target)} · 库存 ${num(startup.proxy_available)} · API ${num(startup.proxy_api_calls)} 次`;
  $('mStartupDevices').textContent = `设备：发现 ${num(startup.device_discovered)} · 读取 ${num(startup.device_loaded)} · 可用 ${num(startup.device_ready)} / 目标 ${num(startup.device_target)} · 注册中 ${num(startup.device_registering)}`;
  $('mStartupHeaders').textContent = `线程：已创建 ${num(startup.threads_created)} / ${num(threads*processes)} · 已占设备 ${num(startup.workers_started)} · 公共头等待 ${num(startup.public_header_waiting)} · 就绪 ${num(startup.public_header_ready)} · 业务请求中 ${num(startup.business_inflight)} · 超时重取 ${num(startup.public_header_retries)} · 并发上限 ${num(startup.public_header_limit)}`;
  $('mStartupProcesses').textContent = `进程：已就绪 ${num(startup.process_ready)} / ${num(startup.process_total)}`;
  const poolAvailable = pool.available == null ? null : Number(pool.available);
  const poolLow = pool.low_water == null ? null : Number(pool.low_water);
  const poolHigh = pool.high_water == null ? null : Number(pool.high_water);
  const poolStateFor = p => !d.running
    ? (d.finished ? '任务结束' : '待启动')
    : p.supplier_alive === false
      ? '供应中断'
      : p.available != null && p.low_water != null && Number(p.available) < Number(p.low_water)
        ? '补货中' : p.available == null ? '等待' : '正常';
  const poolState = poolStateFor(pool);
  const processPools = Array.isArray(pool.by_process) ? pool.by_process : [];
  if(processPools.length > 1){
    const perProcess = processPools.map(p => `P${p.process} `
      + `${p.available == null ? '--' : num(p.available)}`
      + `/${p.low_water == null ? '--' : num(p.low_water)}`
      + `/${p.high_water == null ? '--' : num(p.high_water)} ${poolStateFor(p)}`).join(' · ');
    $('mIpPool').textContent = `IP池 ${perProcess} · 合计 `
      + `${poolAvailable == null ? '--' : num(poolAvailable)}`
      + `/${poolLow == null ? '--' : num(poolLow)}`
      + `/${poolHigh == null ? '--' : num(poolHigh)}`;
  }else{
    $('mIpPool').textContent = `IP池 库存 ${poolAvailable == null ? '--' : num(poolAvailable)}`
      + ` / 低水位 ${poolLow == null ? '--' : num(poolLow)}`
      + ` / 目标 ${poolHigh == null ? '--' : num(poolHigh)} · ${poolState}`;
  }
  $('mIpPool').style.color = poolState === '供应中断' ? 'var(--red)'
    : poolState === '补货中' ? 'var(--amber)'
    : poolState === '正常' ? 'var(--green)' : 'var(--dim)';
  const re = d.register_error_types || {};
  const reTop = Object.entries(re).sort((a,b)=>b[1]-a[1]).slice(0,2)
    .map(([k,v])=>`${k} ${num(v)}`).join(' · ');
  $('mRegErr').textContent = `注册换代理 ${num(d.register_errors)}`
    + (reTop ? ` · ${reTop}` : '');
  $('mEta').textContent = d.eta == null ? '--' : `剩 ${Math.round(d.eta)} 秒`;

  $('stateTag').innerHTML = d.running
    ? `<span class="dot" style="background:var(--blue)"></span>${startupActive ? '启动中 · '+(startupLabels[startup.phase] || '初始化') : '运行中'}`
    : d.finished
      ? `<span class="dot" style="background:var(--green)"></span>${d.status==='complete'?'已完成':'部分完成'}`
      : '<span class="dot" style="background:#9ca3af"></span>已停止';
  // 只有确认状态后才改按钮；fetch 失败时保持原样，避免永久 disabled
  if(typeof d.running === 'boolean'){
    $('start').disabled = d.running;
    $('stop').disabled = !d.running;
  }
  $('modeHint').textContent = startupActive
    ? (startup.message || '正在初始化')
    : d.incomplete ? `⚠ 缺 ${num(d.incomplete)} 条` : '本地执行';

  LAST = d;
  const want = $('filter').value;
  const query = $('resultSearch').value.trim();
  if((!want || want === 'all') && !query) renderRows(); // 查询时不被实时流覆盖
  else if(!HIST) renderRows();

  if(d.accounts && d.accounts !== shownAccounts){
    shownAccounts = d.accounts;
    loadAccounts(d.accounts);
  }
}

let LAST = null;
let HIST = null;          // 筛选时从 /api/results 拿的历史结果
let TICK_RUNNING = false; // 慢请求时不叠加轮询，避免页面突然卡顿
let HIST_SEQ = 0;

function rowHtml(r, idx){
  const st = r.status || 'unknown';
  const att = (r.attempts && r.attempts > 1)
    ? ` <span class="badge b-blue" style="font-size:10px">×${esc(r.attempts)}</span>` : '';
  const seconds = r.ms == null ? '--' : (Number(r.ms) / 1000).toFixed(2);
  const deviceUses = Number(r.device_uses);
  const deviceLimit = Number(r.device_limit);
  const deviceOver = deviceLimit > 0 && deviceUses > deviceLimit;
  const deviceUseText = Number.isFinite(deviceUses) && deviceUses > 0
    ? `${deviceUses}${deviceLimit > 0 ? '/'+deviceLimit : ''}` : '--';
  return `<tr>
    <td class="mono">${esc(idx)}</td>
    <td>${esc(String(r.email||'').slice(0,32)||'--')}</td>
    <td><span class="badge ${cls(st)}">${esc(statusLabel(st))}</span>${att}</td>
    <td class="mono">${seconds}</td>
    <td class="mono">${esc(r.cpu ?? r.thread_cpu_ms ?? '--')}</td>
    <td class="mono">${esc(r.slot ?? '--')}</td>
    <td class="mono">${esc(r.device_id || '--')}</td>
    <td class="mono" style="${deviceOver?'color:var(--red);font-weight:700':''}">
      ${deviceOver?'⚠ ':''}${esc(deviceUseText)}</td>
    <td class="mono">${esc(r.http ?? '--')}</td>
    <td class="mono">${esc(r.ec ?? '--')}</td>
    <td style="font-size:11px">${webReviewHtml(r)}</td>
    <td style="color:#6b7280;font-size:11.5px;max-width:340px;overflow:hidden;
        text-overflow:ellipsis" title="${esc(r.detail||'')}">
      ${esc(String(r.detail||'--').slice(0,64))}</td>
  </tr>`;
}

async function loadHistory(want){
  const seq = ++HIST_SEQ;
  const query = $('resultSearch').value.trim();
  $('tblHint').textContent = '查询中…';
  try{
    const r = await (await fetch(`/api/results?status=${encodeURIComponent(want)}&limit=100&query=${encodeURIComponent(query)}`)).json();
    if(seq !== HIST_SEQ) return;
    HIST = r;
    $('tblHint').textContent = `当前任务共 ${num(r.total)} 条符合条件`;
  }catch(e){ HIST = null; $('tblHint').textContent = '查询失败'; }
  renderRows();
}

function renderRows(){
  const want = $('filter').value;
  const query = $('resultSearch').value.trim();
  const useHist = Boolean(query || (want && want !== 'all'));
  const rec = useHist ? ((HIST && HIST.rows) || [])
                      : ((LAST && LAST.recent) || []).slice().reverse();
  const base = useHist ? (HIST ? HIST.rows.length : 0)
                       : ((LAST && LAST.done) || 0);
  $('rows').innerHTML = rec.length ? rec.map((r,i)=>rowHtml(r, base - i)).join('')
    : `<tr><td colspan="12" style="text-align:center;color:#9ca3af;padding:24px">
        ${useHist ? '这个分类下还没有记录' : '还没有结果'}</td></tr>`;
}

function renderRowsOld(){
  const d = LAST;
  if(!d){ return; }
  const want = $('filter').value;
  let rec = (d.recent||[]).slice().reverse();
  if(want === 'other') rec = rec.filter(r =>
    ['undetermined','error','need_mac'].includes(r.status||''));
  else if(want && want !== 'all') rec = rec.filter(r => (r.status||'') === want);
  $('rows').innerHTML = rec.length ? rec.map((r,i)=>{
    const st = r.status || 'unknown';
    const att = (r.attempts && r.attempts > 1)
      ? ` <span class="badge b-blue" style="font-size:10px">×${esc(r.attempts)}</span>` : '';
    const seconds = r.ms == null ? '--' : (Number(r.ms) / 1000).toFixed(2);
    return `<tr>
      <td class="mono">${esc(d.done-rec.length+i+1)}</td>
      <td>${esc(String(r.email||'').slice(0,32)||'--')}</td>
      <td><span class="badge ${cls(st)}">${esc(statusLabel(st))}</span>${att}</td>
      <td class="mono">${seconds}</td>
      <td class="mono">${esc(r.thread_cpu_ms ?? '--')}</td>
      <td class="mono">${esc(r.slot ?? '--')}</td>
      <td class="mono">${esc(r.http ?? '--')}</td>
      <td class="mono">${esc(r.ec ?? '--')}</td>
      <td style="font-size:11px">${webReviewHtml(r)}</td>
      <td style="color:#6b7280;font-size:11.5px;max-width:340px;overflow:hidden;
          text-overflow:ellipsis" title="${esc(r.detail||'')}">
        ${esc(String(r.detail||'--').slice(0,64))}</td>
    </tr>`;
  }).join('') : `<tr><td colspan="10" style="text-align:center;color:#9ca3af;padding:24px">
    ${want === 'all' ? '还没有结果' : '这个分类下没有结果'}</td></tr>`;
}

async function loadAccounts(path){
  const q = path ? ('&path='+encodeURIComponent(path)) : '';
  const a = await (await fetch('/api/accounts?t='+Date.now()+q)).json();
  renderAccounts(a);
}
loadAccounts(); tick(); setInterval(tick, 1000);
</script></body></html>"""
PAGE = PAGE.replace('__APP_VERSION__', APP_VERSION)


def main():
    global PYTHON
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=8777)
    ap.add_argument('--host', default='0.0.0.0', help='监听地址，默认对外')
    ap.add_argument('--password', default=os.environ.get('GSA_PASSWORD', 'mtx123'),
                    help='控制台密码，默认 mtx123')
    ap.add_argument('--accounts', default=None,
                    help='账号文件；不传时自动恢复最后一次上传')
    ap.add_argument('--python', default=PYTHON)
    args = ap.parse_args()
    STATE['accounts'] = args.accounts or _startup_accounts()
    PYTHON = args.python
    if not os.path.exists(PYTHON):
        print(f'警告: 找不到解释器 {PYTHON}')
    global PASSWORD
    PASSWORD = args.password or 'mtx123'
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f'控制台: http://{args.host}:{args.port}   密码: {PASSWORD}')
    print(f'账号文件: {STATE["accounts"]}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop_job()
        server.shutdown()


if __name__ == '__main__':
    main()
