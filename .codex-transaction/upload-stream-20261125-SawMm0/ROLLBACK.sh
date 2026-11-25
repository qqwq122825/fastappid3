#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo "usage: $0 TARGET_COPY_OR_DIRECTORY" >&2
  exit 64
fi
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGET=$1
if [ -d "$TARGET" ]; then
  mkdir -p "$TARGET/fastcheck" "$TARGET/tests"
  cp "$HERE/device-metrics-baseline/fastcheck/devices.py" "$TARGET/fastcheck/devices.py"
  cp "$HERE/device-metrics-baseline/simple.py" "$TARGET/simple.py"
  cp "$HERE/device-metrics-baseline/run_mp.py" "$TARGET/run_mp.py"
  cp "$HERE/device-metrics-baseline/web.py" "$TARGET/web.py"
  cp "$HERE/device-metrics-baseline/tests/test_error_reporting.py" "$TARGET/tests/test_error_reporting.py"
else
  cp "$HERE/web.py.baseline" "$TARGET"
fi
