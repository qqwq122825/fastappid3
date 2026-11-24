"""纯 CPU 基准：判断是"CPU 单核弱"还是"缺指令集"还是"超卖"。"""
import time, hashlib, platform, sys

try:
    import gmpy2
except ImportError:
    gmpy2 = None

def bench(label, fn, n=1):
    fn()
    t0 = time.thread_time()
    for _ in range(n): fn()
    return (len if False else n and (time.thread_time() - t0) / n * 1000)

print(f'平台: {platform.machine()} | {platform.processor() or "?"}')
try:
    with open('/proc/cpuinfo') as f:
        for line in f:
            if line.startswith('model name'):
                print(line.strip()); break
    with open('/proc/cpuinfo') as f:
        flags = ''
        for line in f:
            if line.startswith('flags'):
                flags = line.split(':',1)[1].split(); break
    want = ['aes','sha_ni','avx2','vaes','adx','bmi2','avx512f']
    print('指令集: ' + '  '.join(f'{w}={"有" if w in flags else "无"}' for w in want))
except OSError:
    pass
print()

def int_loop():
    s = 0
    for i in range(2_000_000):
        s += i * i
    return s
print(f'① 纯整数循环 200万次         {bench("", int_loop, 3):8.2f} ms')

def float_loop():
    s = 0.0
    for i in range(2_000_000):
        s += i * 0.5
    return s
print(f'② 浮点循环 200万次           {bench("", float_loop, 3):8.2f} ms')

payload = b'x' * 1024
def sha():
    for _ in range(200000):
        hashlib.sha256(payload).digest()
print(f'③ SHA256 20万×1KB           {bench("", sha, 1):8.2f} ms')

if gmpy2:
    a = gmpy2.mpz(2)**2048 - 1
    b = gmpy2.mpz(2)**2048 - 159
    def bigmul():
        for _ in range(20000):
            _ = a * b
    print(f'④ 2048位大整数乘法 2万次      {bench("", bigmul, 1):8.2f} ms')

def alloc():
    for _ in range(2000):
        bytearray(1 << 20)
print(f'⑤ 分配 1MB 2000次            {bench("", alloc, 1):8.2f} ms')

# CPU 超卖检测
try:
    import subprocess
    out = subprocess.run(['cat','/proc/stat'], capture_output=True, text=True, timeout=5).stdout
    first = [int(x) for x in out.split('\n')[0].split()[1:]]
    time.sleep(2)
    out = subprocess.run(['cat','/proc/stat'], capture_output=True, text=True, timeout=5).stdout
    second = [int(x) for x in out.split('\n')[0].split()[1:]]
    d = [b - a for a, b in zip(first, second)]
    total = sum(d) or 1
    labels = ['user','nice','system','idle','iowait','irq','softirq','steal']
    parts = [f'{labels[i]}={d[i]/total*100:.1f}%' for i in range(min(len(d), len(labels)))]
    print()
    print('CPU 时间分布: ' + '  '.join(parts))
    if len(d) > 7 and d[7] / total > 0.05:
        print(f'  ⚠ steal={d[7]/total*100:.1f}% —— 虚拟机被超卖，CPU 时间被别人抢走')
except Exception as e:
    pass
