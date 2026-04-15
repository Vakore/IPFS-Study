#!/usr/bin/env python3
"""
08_kubo_rpc.py  —  DAG statistics and DHT provider counts via a local Kubo
                    (go-ipfs) node's RPC API.

Requires a running Kubo node at localhost:5001.
Start one with:  ipfs daemon --init   (first time)
                 ipfs daemon          (subsequent runs)

What this script collects
─────────────────────────
  DAG stats  (dag_stats table)
  ─────────────────────────────
  For every /ipfs/ CID found in the dnslink_records table:
    • size_bytes  — total payload bytes across all blocks in the DAG
    • num_blocks  — number of unique blocks (graph width/depth indicator)
    • size_bucket — 'tiny' (<1 KB) | 'small' (<1 MB) | 'medium' (<1 GB) | 'large'
  This tells us whether DNSLink is being used for personal home pages
  (tiny) or large dataset mirrors (large), testing the bimodal hypothesis.

  Provider records  (provider_records table)
  ─────────────────────────────────────────
  For the same CIDs, issue a DHT FindProviders query:
    • provider_count  — number of unique peers announcing they have the CID
    • has_pinning_svc — True if any provider multiaddr hostname/PeerID matches
                         a known pinning service
  Low provider count (1–2) = fragile, content disappears when the uploader
  goes offline.  High count = robust replication.

Usage:
    ipfs daemon &
    python 08_kubo_rpc.py
    python 08_kubo_rpc.py --workers 5 --rps 3
"""

import argparse
import json
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
from tqdm import tqdm

import db
from config import KUBO_API_BASE, KUBO_TIMEOUT, KUBO_MAX_PROVIDERS, PINNING_SERVICES

# ── Graceful shutdown ───────────────────────────────────────────────────────
_shutdown = False

def _handle_signal(sig, frame):
    global _shutdown
    print("\n[08] Interrupt — saving progress …")
    _shutdown = True

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── Kubo RPC helpers ────────────────────────────────────────────────────────

_session = requests.Session()
_session.headers["User-Agent"] = "IPFS-FieldStudy/2.0"


def _kubo_post(endpoint: str, params: dict) -> dict | list | None:
    """POST to a Kubo RPC endpoint, return parsed JSON or None on error."""
    url = f"{KUBO_API_BASE}/{endpoint}"
    try:
        resp = _session.post(url, params=params, timeout=KUBO_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        return None   # daemon not running
    except Exception:
        return None


def _kubo_post_streaming(endpoint: str, params: dict) -> list[dict]:
    """
    Some Kubo endpoints (findprovs) return newline-delimited JSON.
    Collect all lines and return as a list.
    """
    url = f"{KUBO_API_BASE}/{endpoint}"
    results = []
    try:
        resp = _session.post(url, params=params,
                             timeout=KUBO_TIMEOUT, stream=True)
        resp.raise_for_status()
        for line in resp.iter_lines():
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass
    return results


def check_daemon() -> bool:
    """Return True if the Kubo daemon is reachable."""
    r = _kubo_post("version", {})
    if r:
        print(f"[08] Kubo daemon found — version {r.get('Version', '?')}")
        return True
    print(f"[08] ERROR: Kubo daemon not reachable at {KUBO_API_BASE}")
    print(f"[08]        Start it with:  ipfs daemon")
    return False


# ── Size bucket helper ──────────────────────────────────────────────────────

def size_bucket(bytes_: int | None) -> str:
    if bytes_ is None:
        return "unknown"
    if bytes_ < 1_024:
        return "tiny"            # < 1 KB
    if bytes_ < 1_048_576:
        return "small"           # < 1 MB
    if bytes_ < 1_073_741_824:
        return "medium"          # < 1 GB
    return "large"               # ≥ 1 GB


# ── DAG stats ───────────────────────────────────────────────────────────────

def get_dag_stats(domain: str, cid: str) -> dict:
    """
    Call /api/v0/dag/stat.  Returns a dag_stats row dict.
    Note: dag/stat may time out for very large DAGs; KUBO_TIMEOUT controls this.
    """
    result = {
        "domain": domain, "cid": cid,
        "size_bytes": None, "num_blocks": None,
        "size_bucket": "unknown", "dag_error": None,
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }

    data = _kubo_post("dag/stat", {"arg": cid, "progress": "false"})
    if data is None:
        result["dag_error"] = "rpc_unavailable"
    elif "Size" in data:
        sz = data["Size"]
        result["size_bytes"]  = sz
        result["num_blocks"]  = data.get("NumBlocks")
        result["size_bucket"] = size_bucket(sz)
    elif "Message" in data:
        result["dag_error"] = data["Message"][:200]
    else:
        result["dag_error"] = "unexpected_response"

    return result


# ── Provider count ──────────────────────────────────────────────────────────

# Pinning-service peer-ID / hostname fragments used to identify known
# services among provider multiaddresses.
_PINNING_PEER_HINTS = {
    svc: patterns["rdns"]
    for svc, patterns in PINNING_SERVICES.items()
}


def _detect_pinning_in_providers(providers: list[dict]) -> tuple[bool, str | None]:
    """
    Scan provider multiaddresses for hostnames that match known pinning services.
    Returns (found: bool, service_name | None).
    """
    for peer in providers:
        addrs = peer.get("Addrs") or []
        for addr in addrs:
            addr_lower = addr.lower()
            for svc, hints in _PINNING_PEER_HINTS.items():
                if any(h in addr_lower for h in hints):
                    return True, svc
    return False, None


def get_provider_count(domain: str, cid: str) -> dict:
    """
    Call /api/v0/routing/findprovs and count unique provider peer IDs.
    """
    result = {
        "domain": domain, "cid": cid,
        "provider_count": None,
        "peer_ids_json": None,
        "has_pinning_svc": 0,
        "pinning_svc_name": None,
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }

    events = _kubo_post_streaming(
        "routing/findprovs",
        {"arg": cid, "num-providers": KUBO_MAX_PROVIDERS},
    )

    if not events:
        return result

    # Events are typed; we want Type=4 (Provider) events
    providers = [e for e in events if e.get("Type") == 4]

    # Collect unique peer IDs
    peer_ids = list({p.get("ID", "") for p in providers if p.get("ID")})
    has_pin, pin_svc = _detect_pinning_in_providers(providers)

    result.update({
        "provider_count":  len(peer_ids),
        "peer_ids_json":   json.dumps(peer_ids[:50]),  # cap storage at 50 IDs
        "has_pinning_svc": int(has_pin),
        "pinning_svc_name": pin_svc,
    })
    return result


# ── Worker: fetch both DAG and providers for one CID ───────────────────────

def process_cid(domain: str, cid: str) -> tuple[dict, dict]:
    dag  = get_dag_stats(domain, cid)
    prov = get_provider_count(domain, cid)
    return dag, prov


# ── Database helpers ────────────────────────────────────────────────────────

def _fetch_pending() -> list:
    with db.get_db() as conn:
        return conn.execute("""
            SELECT DISTINCT dr.domain, dr.cid
            FROM   dnslink_records dr
            JOIN   domains d ON d.domain = dr.domain
            WHERE  dr.link_type = 'ipfs' AND dr.cid IS NOT NULL
              AND  d.scanned_dag = 0
            ORDER  BY d.rank ASC
        """).fetchall()


def _save_batch(dag_rows: list[dict], prov_rows: list[dict], domains: list[str]):
    with db.get_db() as conn:
        conn.executemany("""
            INSERT INTO dag_stats
              (domain, cid, size_bytes, num_blocks, size_bucket, dag_error, queried_at)
            VALUES
              (:domain, :cid, :size_bytes, :num_blocks, :size_bucket, :dag_error, :queried_at)
        """, dag_rows)
        conn.executemany("""
            INSERT INTO provider_records
              (domain, cid, provider_count, peer_ids_json,
               has_pinning_svc, pinning_svc_name, queried_at)
            VALUES
              (:domain, :cid, :provider_count, :peer_ids_json,
               :has_pinning_svc, :pinning_svc_name, :queried_at)
        """, prov_rows)
        # Mark BOTH progress flags
        conn.executemany("""
            UPDATE domains SET scanned_dag=1, scanned_providers=1 WHERE domain=?
        """, [(d,) for d in set(domains)])


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DAG stats + DHT provider counts via local Kubo RPC")
    parser.add_argument("--workers", type=int, default=4,
                        help="Concurrent CID queries (keep low; Kubo is single-node)")
    parser.add_argument("--rps",     type=float, default=2.0,
                        help="RPC calls per second (default 2)")
    args = parser.parse_args()

    db.init_db()

    if not check_daemon():
        sys.exit(1)

    pending = _fetch_pending()
    print(f"[08] CIDs to query: {len(pending):,}")
    if not pending:
        print("[08] Nothing pending — run 02_scan_dnslink.py first.")
        return

    delay    = 1.0 / args.rps
    BATCH    = 20
    dag_buf: list[dict]  = []
    prov_buf: list[dict] = []
    dom_buf: list[str]   = []
    errors = 0

    # Size distribution counters for live summary
    buckets = {"tiny": 0, "small": 0, "medium": 0, "large": 0, "unknown": 0}

    with ThreadPoolExecutor(max_workers=args.workers) as pool, \
         tqdm(total=len(pending), desc="DAG + Providers", unit="CIDs") as pbar:

        futures = {}
        for row in pending:
            if _shutdown:
                break
            fut = pool.submit(process_cid, row["domain"], row["cid"])
            futures[fut] = row["domain"]
            time.sleep(delay)

        for fut in as_completed(futures):
            domain = futures.pop(fut)
            try:
                dag, prov = fut.result()
            except Exception as e:
                dag  = {"domain": domain, "cid": None, "size_bytes": None,
                        "num_blocks": None, "size_bucket": "unknown",
                        "dag_error": str(e)[:100],
                        "queried_at": datetime.now(timezone.utc).isoformat()}
                prov = {"domain": domain, "cid": None, "provider_count": None,
                        "peer_ids_json": None, "has_pinning_svc": 0,
                        "pinning_svc_name": None,
                        "queried_at": dag["queried_at"]}
                errors += 1

            dag_buf.append(dag)
            prov_buf.append(prov)
            dom_buf.append(domain)
            buckets[dag["size_bucket"]] = buckets.get(dag["size_bucket"], 0) + 1

            if len(dag_buf) >= BATCH:
                _save_batch(dag_buf, prov_buf, dom_buf)
                dag_buf, prov_buf, dom_buf = [], [], []

            pbar.update(1)
            pbar.set_postfix(errors=errors)

    if dag_buf:
        _save_batch(dag_buf, prov_buf, dom_buf)

    total = len(pending)
    print(f"\n[08] Done — {total:,} CIDs queried ({errors:,} errors).")
    print(f"     Size distribution:")
    for b, n in buckets.items():
        pct = n / total * 100 if total else 0
        print(f"       {b:<10} {n:>5}  ({pct:.1f}%)")


if __name__ == "__main__":
    main()
