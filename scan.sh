#!/usr/bin/env bash
# Cyberloka one-shot scanner wrapper (Linux / macOS / WSL)
#
# Pemakaian:
#   ./scan.sh https://target-anda.com [mode]
#
# mode opsional: passive (default, paling aman) | active | full
#
# Skrip ini akan:
#   1. Bikin venv .venv/ kalau belum ada
#   2. Install dependency
#   3. Jalankan scan
#   4. Tampilkan ringkasan + path file laporan HTML & JSON
#
# WAJIB: hanya scan target yang Anda miliki sendiri / Anda punya izin tertulis.

set -e

TARGET="${1:-}"
MODE="${2:-passive}"

if [ -z "$TARGET" ]; then
    cat <<EOF
Usage: $0 <https://target.com> [passive|active|full]

Contoh:
    $0 https://target-anda.com passive
    $0 http://localhost:3000 active
    $0 https://target-anda.com full
EOF
    exit 2
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# 1) venv
if [ ! -d ".venv" ]; then
    echo "[setup] Membuat virtualenv..."
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# 2) deps
if ! python -c "import requests, rich, jinja2" 2>/dev/null; then
    echo "[setup] Menginstall dependency..."
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
fi

# 3) prep output
mkdir -p reports
TS="$(date +%Y%m%d_%H%M%S)"
HOST_SAFE="$(echo "$TARGET" | sed 's#https\?://##' | tr '/:?&=' '_')"
JSON_OUT="reports/${HOST_SAFE}_${TS}.json"
HTML_OUT="reports/${HOST_SAFE}_${TS}.html"

# 4) scan
echo
echo "============================================================"
echo " CYBERLOKA — Web Vulnerability Scan"
echo " target : $TARGET"
echo " mode   : $MODE"
echo " output : $JSON_OUT"
echo "          $HTML_OUT"
echo "============================================================"
echo

EXTRA=""
if [ "$MODE" != "passive" ]; then
    EXTRA="--authorized --yes --crawl"
fi

# Jalankan; ignore exit 1 (artinya ada finding high/critical, itu memang yang dicari)
set +e
python -m cyberloka -t "$TARGET" --mode "$MODE" $EXTRA \
    --json "$JSON_OUT" --html "$HTML_OUT" --quiet
EXIT=$?
set -e

# 5) ringkasan
echo
echo "============================================================"
if [ -f "$JSON_OUT" ]; then
    python - <<PY
import json, sys
with open("$JSON_OUT") as f:
    d = json.load(f)
s = d.get("summary", {}).get("by_severity", {})
total = d.get("summary", {}).get("total", 0)
print(f"  Total finding : {total}")
print(f"  CRITICAL : {s.get('critical', 0)}")
print(f"  HIGH     : {s.get('high', 0)}")
print(f"  MEDIUM   : {s.get('medium', 0)}")
print(f"  LOW      : {s.get('low', 0)}")
print(f"  INFO     : {s.get('info', 0)}")
print()
hi = [f for f in d.get("findings", []) if f.get("severity") in ("critical", "high")]
if hi:
    print("  Top issues (critical/high):")
    for f in hi[:8]:
        print(f"   - [{f['severity'].upper()}] {f['module']}: {f['title']}")
PY
fi
echo "============================================================"
echo
echo "  HTML report: $HTML_OUT"
echo "  JSON report: $JSON_OUT"
echo
echo "  Untuk diff dengan scan sebelumnya:"
echo "    python -m cyberloka diff <old.json> $JSON_OUT"
echo

exit $EXIT
