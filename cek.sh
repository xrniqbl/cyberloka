#!/usr/bin/env bash
# Cyberloka — pemeriksa kerentanan website (mode interaktif)
#
# Cukup jalankan, masukkan domain/IP, lalu pilih mode 1/2/3.
# Tool akan otomatis:
#   1) install dependency yang dibutuhkan
#   2) scan website
#   3) cetak ringkasan: "Website ini rentan / aman" + daftar celah
#
# WAJIB: hanya gunakan untuk website yang Anda miliki / yang memberi izin.

set -e

TARGET="${1:-}"
MODE_INPUT="${2:-}"

echo
echo "============================================================"
echo "  CYBERLOKA - Pemeriksa Kerentanan Website"
echo "============================================================"
echo

# Minta target kalau belum dikasih
if [ -z "$TARGET" ]; then
    read -rp "Masukkan domain atau IP target: " TARGET
fi

if [ -z "$TARGET" ]; then
    echo "Target tidak boleh kosong. Dibatalkan."
    exit 2
fi

# Tampilkan menu mode kalau belum dikasih
if [ -z "$MODE_INPUT" ]; then
    echo
    echo "Pilih mode scan:"
    echo "  [1] PASSIVE  - paling aman, hanya membaca header/cookies/TLS"
    echo "                 (cocok untuk website apapun)"
    echo "  [2] ACTIVE   - passive + crawler + cek SQLi/XSS/SSRF/JWT/dll."
    echo "                 (butuh izin scan dari pemilik website)"
    echo "  [3] FULL     - active + recon (DNS/port/subdomain/OpenAPI)"
    echo "                 (paling lengkap, butuh izin scan)"
    echo
    read -rp "Pilihan [1-3, default 1]: " MODE_INPUT
    MODE_INPUT="${MODE_INPUT:-1}"
fi

# Normalisasi mode
case "$MODE_INPUT" in
    1|passive|pasif|p) MODE="passive" ;;
    2|active|aktif|a)  MODE="active"  ;;
    3|full|lengkap|l)  MODE="full"    ;;
    *)
        echo "Pilihan tidak dikenal: $MODE_INPUT (gunakan default passive)"
        MODE="passive"
        ;;
esac

# Tambahkan scheme bila tidak ada
if [[ "$TARGET" != http://* && "$TARGET" != https://* ]]; then
    TARGET="https://$TARGET"
fi

echo
echo "Target : $TARGET"
echo "Mode   : $MODE"
echo

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

# Timestamp & sanitised filename (anti-error di shell apapun)
TS="$(python -c 'from datetime import datetime; print(datetime.now().strftime("%Y%m%d_%H%M%S"))')"
SAFE="$(python -c 'import sys,re; t=sys.argv[1]; t=re.sub(r"^https?://","",t); print(re.sub(r"[^A-Za-z0-9._-]","_",t))' "$TARGET")"

JSON_OUT="reports/${SAFE}_${TS}.json"
HTML_OUT="reports/${SAFE}_${TS}.html"
TXT_OUT="reports/${SAFE}_${TS}.txt"

EXTRA=""
if [ "$MODE" != "passive" ]; then
    EXTRA="--authorized --yes --crawl"
fi

echo "Menjalankan scan, mohon tunggu..."
echo

set +e
python -m cyberloka -t "$TARGET" --mode "$MODE" $EXTRA \
    --json "$JSON_OUT" --html "$HTML_OUT" --narrative "$TXT_OUT" \
    --quiet
set -e

echo
echo "============================================================"
echo " HASIL SCAN"
echo "============================================================"
if [ -f "$TXT_OUT" ]; then
    cat "$TXT_OUT"
else
    echo "[error] file laporan tidak terbuat. Cek pesan error di atas."
    exit 1
fi

echo
echo "============================================================"
echo " Laporan tersimpan di:"
echo "   $TXT_OUT   (ringkasan teks bahasa Indonesia)"
echo "   $HTML_OUT  (laporan visual, buka di browser)"
echo "   $JSON_OUT  (data terstruktur)"
echo "============================================================"
