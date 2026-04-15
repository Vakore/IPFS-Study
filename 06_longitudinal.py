#!/usr/bin/env python3
"""
06_longitudinal.py  —  Periodically re-scan DNSLink domains to measure:

    • Content churn: how often does the CID under a domain change?
    • Content persistence: does a live CID stay live across rounds?
    • TTL vs. reality: do CIDs change faster or slower than their DNS TTL implies?

How it works
────────────
  Round 0   — captured by 02_scan_dnslink.py (baseline).
  Round N   — this script re-queries _dnslink.<domain> TXT records and compares
              the CID to the round-0 baseline stored in dnslink_records.
  Each round's result is one row in the longitudinal table.

State file
──────────
  A small JSON file (longitudinal_state.json by default) tracks which round
  is next and when it was last run.  Delete it to start fresh.

Typical schedule
────────────────
  Run this script from cron or a systemd timer once per day:

      0 6 * * *  cd /path/to/study && python 06_longitudinal.py >> logs/longitudinal.log 2>&1

Usage:
    python 06_longitudinal.py                 # run next scheduled round
    python 06_longitudinal.py --force         # run even if interval not elapsed
    python 06_longitudinal.py --round 3       # manually specify round number
    python 06_longitudinal.py --workers 20
"""

import argparse
import json
import os
import signal
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.exception
import dns.flags
import dns.resolver
from tqdm import tqdm

import db
from config import (
    DNS_QPS, DNS_TIMEOUT, DNS_LIFETIME, EDNS_PAYLOAD, RESOLVERS,
    LONGITUDINAL_ROUNDS, LONGITUDINAL_INTERVAL_HOURS, LONGITUDINAL_STATE_FILE,
)

# ── Graceful shutdown ───────────────────────────────────────────────────────
_shutdown = False

def _handle_signal(sig, frame):
    global _shutdown
    print("\n[06] Interrupt — saving progress …")
    _shutdown = True

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── DNS helpers (same logic as 02_scan_dnslink.py) ─────────────────────────
import re
_DNSLINK_RE = re.compile(r"dnslink=(/(?:ipfs|ipns)/[^\s\"']+)", re.IGNORECASE)
_CID_RE     = re.compile(r"/(?:ipfs|ipns)/([^\s/\"']+)")

_resolvers: list[dns.resolver.Resolver] = []

def _init_resolvers():
    global _resolvers
    for ip in RESOLVERS:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [ip]
        r.timeout     = DNS_TIMEOUT
        r.lifetime    = DNS_LIFETIME
        r.use_edns(0, dns.flags.DO, EDNS_PAYLOAD)
        _resolvers.append(r)


def _query_cid(domain: str, idx: int) -> str | None:
    """Return the current CID under _dnslink.<domain>, or None."""
    resolver = _resolvers[idx % len(_resolvers)]
    try:
        ans = resolver.resolve(f"_dnslink.{domain}", "TXT", raise_on_no_answer=False)
        if not ans.rrset:
            return None
        for rdata in ans.rrset:
            txt = b" ".join(rdata.strings).decode("utf-8", errors="replace")
            m = _DNSLINK_RE.search(txt)
            if m:
                c = _CID_RE.search(m.group(1))
                if c:
                    return c.group(1)
    except Exception:
        pass
    return None


# ── State file ──────────────────────────────────────────────────────────────

def _load_state(path: str) -> dict:
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"next_round": 1, "last_run_iso": None, "completed_rounds": []}


def _save_state(path: str, state: dict):
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def _hours_since_last_run(state: dict) -> float:
    lr = state.get("last_run_iso")
    if not lr:
        return float("inf")
    last = datetime.fromisoformat(lr)
    now  = datetime.now(timezone.utc)
    return (now - last).total_seconds() / 3600


# ── Database helpers ────────────────────────────────────────────────────────

def _fetch_baseline_domains() -> list[dict]:
    """Return (domain, baseline_cid) pairs from round-0 dnslink_records."""
    with db.get_db() as conn:
        return conn.execute("""
            SELECT DISTINCT dr.domain, dr.cid AS baseline_cid
            FROM   dnslink_records dr
            WHERE  dr.link_type = 'ipfs'
              AND  dr.cid IS NOT NULL
            ORDER  BY dr.domain ASC
        """).fetchall()


def _already_done_this_round(round_number: int) -> set:
    """Return set of domains already scanned in this round (for resume)."""
    with db.get_db() as conn:
        rows = conn.execute(
            "SELECT domain FROM longitudinal WHERE round_number = ?",
            (round_number,)
        ).fetchall()
    return {r["domain"] for r in rows}


def _save_batch(records: list[dict]):
    with db.get_db() as conn:
        conn.executemany("""
            INSERT INTO longitudinal
              (domain, round_number, cid_at_check, cid_changed, is_live, checked_at)
            VALUES
              (:domain, :round_number, :cid_at_check, :cid_changed, :is_live, :checked_at)
        """, records)


# ── Worker ─────────────────────────────────────────────────────────────────

def check_domain(domain: str, baseline_cid: str, round_number: int, idx: int) -> dict:
    current_cid = _query_cid(domain, idx)
    return {
        "domain":       domain,
        "round_number": round_number,
        "cid_at_check": current_cid,
        "cid_changed":  int(current_cid is not None and current_cid != baseline_cid),
        "is_live":      int(current_cid is not None),
        "checked_at":   datetime.now(timezone.utc).isoformat(),
    }


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Longitudinal DNSLink re-scan")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--qps",     type=int, default=DNS_QPS)
    parser.add_argument("--force",   action="store_true",
                        help="Run even if LONGITUDINAL_INTERVAL_HOURS has not elapsed")
    parser.add_argument("--round",   type=int, default=None,
                        help="Override round number (use for manual re-runs)")
    args = parser.parse_args()

    db.init_db()
    _init_resolvers()

    state = _load_state(LONGITUDINAL_STATE_FILE)

    # ── Guard: interval check ───────────────────────────────────────────────
    hours_since = _hours_since_last_run(state)
    if not args.force and hours_since < LONGITUDINAL_INTERVAL_HOURS:
        remaining = LONGITUDINAL_INTERVAL_HOURS - hours_since
        print(f"[06] Next round in {remaining:.1f}h — use --force to override.")
        return

    round_number = args.round if args.round is not None else state["next_round"]
    if round_number > LONGITUDINAL_ROUNDS:
        print(f"[06] All {LONGITUDINAL_ROUNDS} rounds complete. "
              f"Increase LONGITUDINAL_ROUNDS in config to continue.")
        return

    print(f"[06] === Starting Round {round_number} / {LONGITUDINAL_ROUNDS} ===")

    baseline = _fetch_baseline_domains()
    already  = _already_done_this_round(round_number)
    pending  = [r for r in baseline if r["domain"] not in already]

    print(f"[06] Baseline domains: {len(baseline):,}  |  "
          f"Already done this round: {len(already):,}  |  "
          f"Remaining: {len(pending):,}")

    if not pending:
        print("[06] Round already complete.")
        state["next_round"]        = round_number + 1
        state["last_run_iso"]      = datetime.now(timezone.utc).isoformat()
        state["completed_rounds"].append(round_number)
        _save_state(LONGITUDINAL_STATE_FILE, state)
        return

    delay   = 1.0 / args.qps
    BATCH   = 100
    batch   = []
    changed = 0
    offline = 0
    idx     = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool, \
         tqdm(total=len(pending), desc=f"Round {round_number}", unit="domains") as pbar:

        futures = {}
        for row in pending:
            if _shutdown:
                break
            fut = pool.submit(check_domain, row["domain"], row["baseline_cid"],
                              round_number, idx)
            futures[fut] = row["domain"]
            idx += 1
            time.sleep(delay)

        for fut in as_completed(futures):
            futures.pop(fut)
            try:
                r = fut.result()
            except Exception as e:
                r = {
                    "domain": "?", "round_number": round_number,
                    "cid_at_check": None, "cid_changed": 0,
                    "is_live": 0,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }

            batch.append(r)
            if r["cid_changed"]:
                changed += 1
            if not r["is_live"]:
                offline += 1

            if len(batch) >= BATCH:
                _save_batch(batch)
                batch = []

            pbar.update(1)
            pbar.set_postfix(changed=changed, offline=offline)

    if batch:
        _save_batch(batch)

    # ── Update state ────────────────────────────────────────────────────────
    if not _shutdown:
        state["next_round"]        = round_number + 1
        state["last_run_iso"]      = datetime.now(timezone.utc).isoformat()
        state["completed_rounds"].append(round_number)
        _save_state(LONGITUDINAL_STATE_FILE, state)

    total = len(pending)
    print(f"\n[06] Round {round_number} done.")
    print(f"     CID changed : {changed:,} / {total:,} ({changed/total*100:.1f}%)")
    print(f"     Offline     : {offline:,} / {total:,} ({offline/total*100:.1f}%)")
    print(f"     State saved → {LONGITUDINAL_STATE_FILE}")


if __name__ == "__main__":
    main()
