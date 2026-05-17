# Cyberloka Test Lab

Lab Docker yang **sengaja rentan** untuk berlatih dan menguji Cyberloka secara legal.

> ⚠️ **Hanya untuk lokal**. Jangan publish port ini ke internet. Compose file
> mengikat semua port ke `127.0.0.1` agar tidak terpapar tanpa sengaja.

## Memulai

```bash
cd lab
docker compose up -d
docker compose ps
```

Tunggu 10-30 detik agar service siap, lalu lakukan post-setup masing-masing app:

| App | URL | Setup pertama | Login |
|-----|-----|----------------|-------|
| OWASP Juice Shop | http://localhost:3000 | langsung jalan | buat akun via UI |
| DVWA | http://localhost:8080 | buka `/setup.php` -> "Create / Reset Database" | `admin / password` |
| bWAPP | http://localhost:8888 | buka `/install.php` sekali | `bee / bug` |
| VAmPI | http://localhost:5001 | `curl -s http://localhost:5001/createdb` | bearer token didapat dari `/users/v1/login` |

## Contoh perintah Cyberloka

### Juice Shop — scan penuh
```bash
python -m cyberloka -t http://localhost:3000 \
  --mode full --authorized \
  --crawl --crawl-max-pages 80 \
  --html lab/reports/juiceshop.html \
  --json lab/reports/juiceshop.json
```

### DVWA — login form lalu scan
```bash
# Sebelum: pastikan DVWA Security = low
python -m cyberloka -t http://localhost:8080 \
  --mode active --authorized \
  --auth-method form \
  --auth-login-url http://localhost:8080/login.php \
  --auth-user admin --auth-pass password \
  --auth-success-marker "Welcome to Damn Vulnerable" \
  --auth-failure-marker "Login failed" \
  --crawl \
  --html lab/reports/dvwa.html
```

### VAmPI — JWT audit + SSRF
```bash
# Buat user & ambil token
curl -s -X POST http://localhost:5001/users/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test","email":"t@t"}'
TOKEN=$(curl -s -X POST http://localhost:5001/users/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' | jq -r .auth_token)

python -m cyberloka -t http://localhost:5001 \
  --modules crawler,jwt,ssrf,headers,cors \
  --auth-method bearer --auth-token "$TOKEN" \
  --authorized \
  --html lab/reports/vampi.html
```

### bWAPP — modul terfokus pada SQLi/XSS/LFI/CmdI
```bash
python -m cyberloka -t http://localhost:8888 \
  --modules crawler,sqli,xss,lfi,cmdi,redirect \
  --auth-method form \
  --auth-login-url http://localhost:8888/login.php \
  --auth-user bee --auth-pass bug \
  --authorized
```

## Membersihkan

```bash
docker compose down -v
```

## Hasil yang diharapkan

Saat di-scan, lab ini akan menunjukkan banyak finding **CRITICAL/HIGH**. Itu memang
tujuannya — Anda dapat melihat output Cyberloka dalam kondisi nyata, dan
membandingkannya dengan walkthrough resmi tiap aplikasi:

- Juice Shop: https://pwning.owasp-juice.shop/
- DVWA: https://github.com/digininja/DVWA
- bWAPP: http://www.itsecgames.com/
- VAmPI: https://github.com/erev0s/VAmPI
