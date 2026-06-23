# Port scan: layanan harus TERKONFIRMASI, bukan diprediksi dari nomor port

- **Tanggal:** 2026-06-23
- **Modul terdampak:** `cyberloka/recon/ports.py`
- **Versi:** v0.10.6

## Pertanyaan yang dijawab
"Pada port apakah scan itu benar-benar yang terbuka atau hanya prediksi saja?"

### Status APA ADANYA (sudah benar)
- **Keterbukaan port = NYATA.** `_check_port` memakai `socket.create_connection`
  (handshake TCP sungguhan) ke daftar ~60 port umum (`COMMON_PORTS`). Port hanya
  dianggap terbuka bila handshake sukses — bukan prediksi.
- **Probe layanan dalam = NYATA.** Redis (`+PONG`), MongoDB (`ismaster`), Docker
  (`/version` `ApiVersion`), Elasticsearch (`cluster_name`), Memcached (`stats`),
  FTP anonymous (`230`) — semua mengirim perintah protokol & memverifikasi isi
  respons. Ini bukti, bukan tebakan.

### Kelemahan "prediksi" yang DIPERBAIKI
Tiga tempat dulu menyimpulkan layanan dari NOMOR PORT, bukan dari bukti:

1. **`INSECURE_PLAINTEXT`** — dulu HIGH "service plaintext X" hanya karena port
   terbuka, nama layanan diasumsikan dari nomor port (port 21 ⇒ "FTP"). **Fix:**
   wajib banner mengkonfirmasi layanan (`_plaintext_confirmed`); bila banner tidak
   konklusif → diturunkan ke **INFO/tentative** dengan judul "Port terbuka
   (layanan belum terverifikasi)" — tidak lagi HIGH palsu.
2. **`_probe_rdp` (3389)** — dulu HIGH hanya dari port terbuka. **Fix:** kirim
   X.224 Connection Request (non-destruktif) dan wajib server membalas TPKT
   (`0x03 0x00`) sebelum melaporkan. Tanpa handshake RDP → tidak ada finding.
3. **SMTP open-relay (25/587)** — dulu HIGH dari satu `RCPT 250`. **Fix:** wajib
   `MAIL FROM` 250 DAN `RCPT TO` eksternal 250; confidence `firm` + catatan bahwa
   konfirmasi DATA tidak dilakukan (verifikasi manual).

## Pencegahan regresi
`tests/test_ports_verification.py`:
- `_plaintext_confirmed` hanya True dengan banner valid.
- RDP: confirmed hanya saat TPKT; ditolak tanpa handshake.
- SMTP: open-relay terdeteksi saat 250/250; ditolak saat RCPT 554.

Suite penuh: **38 passed, 1 skipped**.

## Catatan
Modul `docker_remote_api`, `elasticsearch_unauth`, `prometheus_unauth` mencoba
`CANDIDATE_PORTS` via HTTP GET — bila port tertutup, koneksi gagal (skip), dan
temuan baru muncul bila konten respons cocok signature (ApiVersion / version dict
/ `# HELP`). Jadi itu juga terverifikasi konten, bukan sekadar prediksi port.
