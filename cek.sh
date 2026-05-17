#!/usr/bin/env bash
# Cyberloka — pemeriksa kerentanan website (mode super sederhana)
#
# Cukup masukkan domain atau IP, tool akan otomatis:
#   1) install dependency yang dibutuhkan
#   2) scan website (mode passive yang aman)
#   3) cetak: "Website ini rentan / aman" + daftar celah dalam bahasa Indonesia
#
# Pemakaian:
#   ./cek.sh example.com                # passive (default, hanya membaca)
#   ./cek.sh https://example.com aktif  # tambah scan aktif (butuh izin scan)
#
# WAJIB: hanya gunakan untuk website yang Anda miliki / yang memberi izin.

set -e

TARGET="${1:-}"
MODE_INPUT="${2:-passive}"

if [ -z "$TARGET" ]; then
    cat <<'EOF'
Cyberloka — pemeriksa kerentanan website

Cara pakai:
    ./cek.sh <domain-atau-ip>           # mode aman (passive)
    ./cek.sh <domain-atau-ip> aktif     # tambah scan aktif

Contoh:
    ./cek.sh example.com
    ./cek.sh https://target-anda.com aktif
    ./cek.sh 192.168.1.10
EOF
    exit 2
fi

# Normalisasi mode
case "$MODE_INPUT" in
    passive|pasif|p) MODE="passive" ;;
    active|aktif|a)  MODE="active"  ;;
    full|lengkap|l)  MODE="full"    ;;
    *) MODE="passive" ;;
esac

# Tambahkan scheme bila tidak ada
if [[ "$TARGET" != http://* && "$TARGET" != https://* ]]; then
    TARGET="https://$TARGET"
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# Setup venv & deps
if [ ! -d ".venv" ]; then
    echo "[setup] Menyiapkan environment Python..."
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

if ! python -c "import requests, rich, jinja2" 2>/dev/null; then
    echo "[setup] Menginstall dependency..."
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
fi

mkdir -p reports
TS="$(date +%Y%m%d_%H%M%S)"
SAFE="$(echo "$TARGET" | sed 's#https\?://##' | tr '/:?&=' '_')"
JSON_OUT="reports/${SAFE}_${TS}.json"
HTML_OUT="reports/${SAFE}_${TS}.html"
TXT_OUT="reports/${SAFE}_${TS}.txt"

EXTRA=""
if [ "$MODE" != "passive" ]; then
    EXTRA="--authorized --yes --crawl"
fi

# Jalankan; tetap lanjut walau exit code != 0
set +e
python -m cyberloka -t "$TARGET" --mode "$MODE" $EXTRA \
    --json "$JSON_OUT" --html "$HTML_OUT" --narrative "$TXT_OUT" \
    --quiet
set -e

echo
echo "Laporan tersimpan di:"
echo "   $TXT_OUT   (ringkasan teks)"
echo "   $HTML_OUT  (laporan visual)"
echo "   $JSON_OUT  (data terstruktur)"
echo
