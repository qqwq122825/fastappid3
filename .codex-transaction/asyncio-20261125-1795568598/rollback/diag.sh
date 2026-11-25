#!/bin/bash
# 服务器自查脚本：定位 502 / 点开始没反应
# 用法：bash diag.sh [端口]
PORT="${1:-8765}"
PROJ="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJ" || exit 1

echo "================ 1. 代码版本 ================"
if grep -q "def is_running" web.py 2>/dev/null; then
  echo "  ✅ web.py 含 is_running()（新版）"
else
  echo "  ❌ web.py 缺 is_running()——这是旧版本，必须重新解压覆盖"
fi
if grep -q "_do_post" web.py 2>/dev/null; then
  echo "  ✅ web.py 含异常捕获（新版）"
else
  echo "  ❌ web.py 无异常捕获——旧版本，出错会直接 502"
fi
echo "  web.py 修改时间: $(stat -c '%y' web.py 2>/dev/null || stat -f '%Sm' web.py 2>/dev/null)"

echo
echo "================ 2. 进程与端口 ================"
ps -eo pid,etime,rss,args | grep -E "web\.py|run_mp|simple\.py" | grep -v grep || echo "  （没有相关进程）"
echo
LISTEN=""
if command -v ss >/dev/null 2>&1; then
  LISTEN=$(ss -ltn 2>/dev/null | grep ":$PORT ")
elif command -v netstat >/dev/null 2>&1; then
  LISTEN=$(netstat -ltn 2>/dev/null | grep ":$PORT ")
fi
if [ -n "$LISTEN" ]; then
  echo "  ✅ 端口 $PORT 在监听"
elif curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$PORT/" 2>/dev/null; then
  echo "  ✅ 端口 $PORT 可访问（检测工具不可用，用 curl 确认）"
else
  echo "  ❌ 端口 $PORT 没监听也没响应"
fi

echo
echo "================ 3. 直连后端（绕过 Nginx）================"
if command -v curl >/dev/null 2>&1; then
  echo -n "  GET /            → "
  curl -s -o /dev/null -w "HTTP %{http_code}  %{time_total}s\n" \
       --max-time 10 "http://127.0.0.1:$PORT/" || echo "连不上"
  echo -n "  GET /api/live    → "
  curl -s -o /dev/null -w "HTTP %{http_code}  %{time_total}s\n" \
       --max-time 10 "http://127.0.0.1:$PORT/api/live" || echo "连不上"
else
  echo "  没有 curl，装一下：apt install -y curl"
fi

echo
echo "================ 4. 依赖自检 ================"
PY=".venv/bin/python"; [ -x "$PY" ] || PY="python3"
[ -x "$PY" ] && echo "  Python: $($PY -V 2>&1)"
for mod in requests socks gmpy2; do
  if $PY -c "import $mod" 2>/dev/null; then
    echo "  ✅ $mod"
  else
    echo "  ❌ $mod 缺失 → $PY -m pip install $mod"
  fi
done
$PY -c "import ssl;print('  CA 证书:',len(ssl.create_default_context().get_ca_certs()))" 2>/dev/null

echo
echo "================ 4b. 内置 fastcheck ================"
if [ -d fastcheck ]; then
  echo "  ✅ 包内 fastcheck/ 存在（$(find fastcheck -name '*.py' | wc -l) 个模块）"
  for m in protocols/gsa_status protocols/idmsa protocols/srp_auth \
           protocols/anisette_v3 protocols/apple_trust protocols/tls \
           protocols/timing protocols/network_timing devices status; do
    [ -f "fastcheck/$m.py" ] && echo "     ✅ $m" || echo "     ❌ 缺 $m.py"
  done
  echo -n "  import 自检: "
  $PY -c "import sys;sys.path.insert(0,'.');import fastcheck.protocols.gsa_status as g;print('OK', g.__file__)" 2>&1 | tail -1
else
  echo "  ❌ 包内没有 fastcheck/ 目录——子进程会 import 失败直接退出"
fi

echo
echo "================ 5. 权限 ================"
for d in data data/uploads data/devices; do
  if [ -d "$d" ]; then
    if [ -w "$d" ]; then echo "  ✅ $d 可写 ($(stat -c '%U:%G' "$d" 2>/dev/null))"
    else echo "  ❌ $d 不可写 → chown -R www:www $d"; fi
  else
    echo "  ⚠ $d 不存在"
  fi
done

echo
echo "================ 6. 资源 ================"
if command -v free >/dev/null 2>&1; then free -h | head -2; fi
echo "  负载: $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || uptime | sed 's/.*load average: //')"
echo "  当前 shell 句柄上限: $(ulimit -n)  （硬限制 $(ulimit -Hn)）"
echo "  内核单进程上限 (fs.nr_open): $(cat /proc/sys/fs/nr_open 2>/dev/null || echo n/a)"
echo "  内核全局上限 (fs.file-max): $(cat /proc/sys/fs/file-max 2>/dev/null || echo n/a)"
# 关键：看真实进程拿到的限制，而不是 shell 的
for P in $(pgrep -f "web\.py|run_mp\.py|simple\.py" 2>/dev/null | head -3); do
  LIM=$(grep -i "open files" /proc/$P/limits 2>/dev/null | awk '{print $4}')
  NAME=$(ps -o args= -p $P 2>/dev/null | cut -c1-40)
  if [ -n "$LIM" ]; then
    if [ "$LIM" -lt 10000 ] 2>/dev/null; then
      echo "  ❌ pid $P 实际 fd 上限只有 $LIM  → 跑不了 1000 线程"
      echo "     $NAME"
    else
      echo "  ✅ pid $P 实际 fd 上限 $LIM"
    fi
  fi
done
N=$(ps -eo args | grep -c "[s]imple.py")
echo "  simple.py 子进程数: $N"

echo
echo "================ 7. 日志 ================"
if [ -f data/web-error.log ]; then
  echo "  --- data/web-error.log 最后 20 行 ---"
  tail -20 data/web-error.log
else
  echo "  （无 data/web-error.log，说明后端没抛过异常）"
fi
if [ -f data/run.log ]; then
  echo "  --- data/run.log 最后 6 行 ---"
  grep -v Warning data/run.log | tail -6
fi

echo
echo "================ 结论提示 ================"
cat <<'EOF'
  · 第 1 项有 ❌  → 代码是旧的，重新解压 gsa-fast.tar.gz 覆盖后重启宝塔项目
  · 第 3 项 200 但浏览器 502 → 是 Nginx 反代的问题：
        1) 关掉宝塔的「外网映射」
        2) 安全组直接放行端口，访问 http://服务器IP:端口
  · 第 3 项本身就 502/000 → web.py 没在跑，看宝塔「项目日志」
  · 第 5 项 data/ 不可写 → chown -R www:www data
EOF
