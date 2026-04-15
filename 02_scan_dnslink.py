#!/usr/bin/env python3
"""
02_scan_dnslink.py  —  Query _dnslink.<domain> TXT records for every domain
                        in the database.

Supports two backends:
  • dnspython  (default, pure-Python, ~40 q/s)
  • zdns       (optional Go tool, ~thousands q/s; set USE_ZDNS=True in config)

Interruption-safe: progress is written per-domain and the script resumes
from where it left off if killed (Ctrl-C or SIGTERM).

Usage:
    python 02_scan_dnslink.py
    python 02_scan_dnslink.py --workers 20 --limit 5000
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver
from tqdm import tqdm

import db
from config import (
    DB_PATH,
    DNS_QPS,
    DNS_TIMEOUT,
    DNS_LIFETIME,
    EDNS_PAYLOAD,
    RESOLVERS,
    USE_ZDNS,
    ZDNS_THREADS,
    ZDNS_TIMEOUT,
)

# ── Globals for graceful shutdown ──────────────────────────────────────────
_shutdown = False


def _handle_signal(sig, frame):
    global _shutdown
    print("\n[02] Interrupt received — finishing current batch, then exiting …")
    _shutdown = True


signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ── Regex to extract the CID/path from a dnslink value ────────────────────
_DNSLINK_RE = re.compile(r"dnslink=(/(?:ipfs|ipns)/[^\s\"']+)", re.IGNORECASE)
_CID_RE     = re.compile(r"/(?:ipfs|ipns)/([^\s/\"']+)")


def _parse_dnslink_txt(txt: str):
    """Return (link_type, cid, raw_value) or (None, None, None) if not a dnslink record."""
    m = _DNSLINK_RE.search(txt)
    if not m:
        return None, None, None
    raw_value = m.group(1)                        # e.g. /ipfs/Qm…
    parts = raw_value.strip("/").split("/", 1)    # ['ipfs', 'Qm…']
    link_type = parts[0].lower() if parts else "unknown"
    c = _CID_RE.search(raw_value)
    cid = c.group(1) if c else None
    return link_type, cid, raw_value


# ── dnspython backend ──────────────────────────────────────────────────────

_resolver_pool = []   # shared resolver objects, one per configured IP

def _build_resolver(server_ip: str) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers  = [server_ip]
    r.timeout      = DNS_TIMEOUT
    r.lifetime     = DNS_LIFETIME
    r.use_edns(0, dns.flags.DO, EDNS_PAYLOAD)
    return r


def _query_dnslink_dnspython(domain: str, resolver_idx: int = 0):
    """
    Query _dnslink.<domain> via dnspython.

    Returns a list of dicts (one per TXT RR that looks like a dnslink record),
    or an empty list if nothing found.
    """
    name = f"_dnslink.{domain}"
    resolver = _resolver_pool[resolver_idx % len(_resolver_pool)]
    results = []

    try:
        ans = resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers,
            dns.resolver.NoMetaData, Exception):
        return []

    if ans.rrset is None:
        return []

    ttl = ans.rrset.ttl
    for rdata in ans.rrset:
        txt = b" ".join(rdata.strings).decode("utf-8", errors="replace")
        link_type, cid, raw_value = _parse_dnslink_txt(txt)
        if link_type:
            results.append({
                "domain":     domain,
                "link_type":  link_type,
                "cid":        cid,
                "raw_value":  raw_value,
                "raw_txt":    txt,
                "ttl":        ttl,
                "queried_at": datetime.now(timezone.utc).isoformat(),
            })
    return results


# ── zdns backend ───────────────────────────────────────────────────────────

def _run_zdns(domains: list[str]) -> list[dict]:
    """
    Write domains to a temp file, run zdns, parse JSON output.
    Requires `zdns` on PATH (go install github.com/zmap/zdns@latest).
    """
    results = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        input_path = tf.name
        for d in domains:
            tf.write(f"_dnslink.{d}\n")

    output_path = input_path + ".out"
    cmd = [
        "zdns", "TXT",
        "--input-file",   input_path,
        "--output-file",  output_path,
        "--threads",      str(ZDNS_THREADS),
        "--timeout",      str(ZDNS_TIMEOUT),
        "--name-servers", ",".join(RESOLVERS),
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=3600)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[02][zdns] ERROR: {e}")
        return []

    domain_map = {f"_dnslink.{d}": d for d in domains}

    with open(output_path, encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            queried_name = obj.get("name", "").rstrip(".")
            original_domain = domain_map.get(queried_name, queried_name)
            if obj.get("status") != "NOERROR":
                continue
            for answer in obj.get("data", {}).get("answers", []):
                txt = answer.get("answer", "")
                link_type, cid, raw_value = _parse_dnslink_txt(txt)
                if link_type:
                    results.append({
                        "domain":     original_domain,
                        "link_type":  link_type,
                        "cid":        cid,
                        "raw_value":  raw_value,
                        "raw_txt":    txt,
                        "ttl":        answer.get("ttl", 0),
                        "queried_at": datetime.now(timezone.utc).isoformat(),
                    })

    os.unlink(input_path)
    os.unlink(output_path)
    return results


# ── Database helpers ────────────────────────────────────────────────────────

def _save_results(results: list[dict], domains: list[str]):
    """Persist dnslink records and mark domains as scanned."""
    with db.get_db() as conn:
        if results:
            conn.executemany(
                """INSERT INTO dnslink_records
                   (domain, link_type, cid, raw_value, raw_txt, ttl, queried_at)
                   VALUES (:domain, :link_type, :cid, :raw_value, :raw_txt, :ttl, :queried_at)""",
                results,
            )
        conn.executemany(
            "UPDATE domains SET scanned_dnslink = 1 WHERE domain = ?",
            [(d,) for d in domains],
        )


def _fetch_pending(limit: int | None = None) -> list[tuple]:
    """Return list of (id, domain) rows not yet scanned for dnslink."""
    with db.get_db() as conn:
        sql = "SELECT id, domain FROM domains WHERE scanned_dnslink = 0 ORDER BY rank ASC"
        if limit:
            sql += f" LIMIT {limit}"
        return conn.execute(sql).fetchall()


# ── Main ───────────────────────────────────────────────────────────────────

def scan_dnspython(pending: list, workers: int, qps: int):
    """Thread-pool scan using dnspython."""
    delay = 1.0 / qps
    found_total = 0
    BATCH = workers * 4   # write to DB every N completions

    futures_map = {}
    batch_results = []
    batch_domains = []

    with ThreadPoolExecutor(max_workers=workers) as pool, \
         tqdm(total=len(pending), desc="Scanning DNSLink", unit="domains") as pbar:

        resolver_idx = 0
        submitted = 0

        for row in pending:
            if _shutdown:
                break
            fut = pool.submit(_query_dnslink_dnspython, row["domain"], resolver_idx % len(_resolver_pool))
            futures_map[fut] = row["domain"]
            resolver_idx += 1
            submitted += 1
            time.sleep(delay)

        for fut in as_completed(futures_map):
            if _shutdown and not futures_map:
                break
            domain = futures_map.pop(fut)
            try:
                hits = fut.result()
            except Exception as exc:
                hits = []
                print(f"\n[02] Error on {domain}: {exc}", file=sys.stderr)

            batch_results.extend(hits)
            batch_domains.append(domain)
            found_total += len(hits)

            if len(batch_domains) >= BATCH:
                _save_results(batch_results, batch_domains)
                batch_results, batch_domains = [], []

            pbar.update(1)
            pbar.set_postfix(found=found_total)

    if batch_domains:
        _save_results(batch_results, batch_domains)

    return found_total


def scan_zdns(pending: list):
    """Bulk scan using zdns."""
    domains = [r["domain"] for r in pending]
    CHUNK = 50_000
    found_total = 0

    for i in range(0, len(domains), CHUNK):
        if _shutdown:
            break
        chunk = domains[i : i + CHUNK]
        print(f"[02][zdns] Processing chunk {i}–{i+len(chunk)} …")
        results = _run_zdns(chunk)
        found_domains = {r["domain"] for r in results}
        _save_results(results, chunk)
        found_total += len(results)
        print(f"[02][zdns] Chunk done — {len(results)} dnslink records found.")

    return found_total


def main():
    parser = argparse.ArgumentParser(description="Scan domains for DNSLink TXT records")
    parser.add_argument("--workers", type=int, default=20,
                        help="Thread-pool size for dnspython backend (default 20)")
    parser.add_argument("--qps",     type=int, default=DNS_QPS,
                        help="Queries per second (dnspython backend)")
    parser.add_argument("--limit",   type=int, default=0,
                        help="Only process N pending domains (0 = all)")
    args = parser.parse_args()

    db.init_db()

    # Build resolver pool
    global _resolver_pool
    _resolver_pool = [_build_resolver(ip) for ip in RESOLVERS]
    print(f"[02] Using resolvers: {RESOLVERS}")

    pending = _fetch_pending(args.limit or None)
    print(f"[02] Domains to scan: {len(pending):,}")

    if not pending:
        print("[02] Nothing to scan — run 01_fetch_domains.py first.")
        return

    if USE_ZDNS:
        print("[02] Backend: zdns")
        found = scan_zdns(pending)
    else:
        print(f"[02] Backend: dnspython  workers={args.workers}  qps={args.qps}")
        found = scan_dnspython(pending, args.workers, args.qps)

    print(f"\n[02] Done — {found:,} DNSLink records found across {len(pending):,} domains.")


if __name__ == "__main__":
    main()
