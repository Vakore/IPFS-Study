#!/usr/bin/env python3
"""
03_validate_dnssec.py  —  DNSSEC validation for ALL domains that have a
                           DNSLink record, including those with zero DNSSEC.

Key changes from v1
───────────────────
  • Every DNSLink domain gets a row in dnssec_results (no silent skips).
  • Results are classified into 5 buckets via db.classify_dnssec():
      full            – complete chain (DNSKEY + DS + RRSIG + AD flag)
      partial_no_ds   – zone signed but DS not registered at registrar
      partial_no_rrsig– DS registered but _dnslink TXT is unsigned
      broken          – RRSIG present but chain fails (expired / wrong key)
      none            – no DNSSEC infrastructure at all
  • The bucket distribution is what actually tells the paper's story: most
    operators will fall in 'none', a few in 'partial_no_ds', very few in 'full'.

Checks performed per domain
────────────────────────────
  1. AD bit   – validating resolver signals Authenticated Data
  2. DNSKEY   – zone apex publishes at least one DNSKEY RR
  3. DS       – parent zone has a DS delegation signer record
  4. RRSIG    – _dnslink TXT rrset is signed (RRSIG in answer)
  5. Classify → bucket

Usage:
    python 03_validate_dnssec.py
    python 03_validate_dnssec.py --workers 10 --qps 20
"""

import argparse
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
from tqdm import tqdm

import db
from config import DNS_QPS, DNS_TIMEOUT, DNS_LIFETIME, EDNS_PAYLOAD, RESOLVERS

# ── Graceful shutdown ───────────────────────────────────────────────────────
_shutdown = False

def _handle_signal(sig, frame):
    global _shutdown
    print("\n[03] Interrupt — finishing current batch …")
    _shutdown = True

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── Resolver pool ───────────────────────────────────────────────────────────
_resolvers: list[dns.resolver.Resolver] = []

def _init_resolvers():
    for ip in RESOLVERS:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [ip]
        r.timeout     = DNS_TIMEOUT
        r.lifetime    = DNS_LIFETIME
        r.use_edns(0, dns.flags.DO, EDNS_PAYLOAD)
        _resolvers.append(r)


# ── Individual checks ───────────────────────────────────────────────────────

def _check_ad_bit(domain: str, resolver: dns.resolver.Resolver) -> tuple[bool, str | None]:
    """
    Send a query with the AD bit set and inspect the response AD flag.
    A DNSSEC-validating resolver (1.1.1.1, 9.9.9.9) sets AD=1 only when
    the full chain from root → zone is intact.
    """
    try:
        qname   = dns.name.from_text(f"_dnslink.{domain}")
        request = dns.message.make_query(qname, dns.rdatatype.TXT, want_dnssec=True)
        request.flags |= dns.flags.AD
        resp = dns.query.udp(request, resolver.nameservers[0], timeout=DNS_TIMEOUT)
        return bool(resp.flags & dns.flags.AD), None
    except dns.exception.Timeout:
        return False, "timeout"
    except Exception as e:
        return False, str(e)[:80]


def _check_dnskey(domain: str, resolver: dns.resolver.Resolver) -> bool:
    try:
        ans = resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        return ans.rrset is not None and len(ans.rrset) > 0
    except Exception:
        return False


def _check_ds(domain: str, resolver: dns.resolver.Resolver) -> bool:
    """
    DS lives in the *parent* zone.  Querying the domain for DS causes the
    resolver to look one level up — exactly what we want.
    """
    try:
        ans = resolver.resolve(domain, "DS", raise_on_no_answer=False)
        return ans.rrset is not None and len(ans.rrset) > 0
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return False


def _check_rrsig_on_txt(domain: str, resolver: dns.resolver.Resolver) -> bool:
    """
    Request the _dnslink TXT rrset with want_dnssec=True so the resolver
    includes RRSIGs in the answer section.
    """
    try:
        ans = resolver.resolve(
            f"_dnslink.{domain}", "TXT",
            want_dnssec=True, raise_on_no_answer=False,
        )
        if ans.response is None:
            return False
        for rrset in ans.response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                return True
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return False


# ── Per-domain validation ───────────────────────────────────────────────────

def validate_domain(domain: str, resolver: dns.resolver.Resolver) -> dict:
    result = {
        "domain":           domain,
        "has_dnskey":       0,
        "has_ds":           0,
        "has_rrsig_txt":    0,
        "chain_valid":      0,
        "ad_flag":          0,
        "dnssec_class":     "none",
        "validation_error": None,
        "queried_at":       datetime.now(timezone.utc).isoformat(),
    }

    try:
        ad, ad_err = _check_ad_bit(domain, resolver)
        result["ad_flag"] = int(ad)
        if ad_err and not ad:
            result["validation_error"] = f"AD: {ad_err}"

        result["has_dnskey"]    = int(_check_dnskey(domain, resolver))
        result["has_ds"]        = int(_check_ds(domain, resolver))
        result["has_rrsig_txt"] = int(_check_rrsig_on_txt(domain, resolver))

        result["chain_valid"] = int(
            result["has_dnskey"] and
            result["has_ds"] and
            result["has_rrsig_txt"] and
            result["ad_flag"]
        )

        result["dnssec_class"] = db.classify_dnssec(
            result["has_dnskey"], result["has_ds"],
            result["has_rrsig_txt"], result["chain_valid"],
        )

    except Exception as e:
        result["validation_error"] = str(e)[:200]
        result["dnssec_class"]     = "none"

    return result


# ── Database helpers ────────────────────────────────────────────────────────

def _fetch_pending() -> list:
    """
    All domains that have a DNSLink record but no DNSSEC result yet.
    Crucially we do NOT filter to only DNSSEC-looking domains — every
    DNSLink domain must get a row so the bucket distribution is accurate.
    """
    with db.get_db() as conn:
        return conn.execute("""
            SELECT DISTINCT d.domain
            FROM   domains d
            JOIN   dnslink_records dr ON dr.domain = d.domain
            WHERE  d.scanned_dnssec = 0
            ORDER  BY d.rank ASC
        """).fetchall()


def _save_batch(results: list[dict]):
    with db.get_db() as conn:
        conn.executemany("""
            INSERT INTO dnssec_results
              (domain, has_dnskey, has_ds, has_rrsig_txt,
               chain_valid, ad_flag, dnssec_class, validation_error, queried_at)
            VALUES
              (:domain, :has_dnskey, :has_ds, :has_rrsig_txt,
               :chain_valid, :ad_flag, :dnssec_class, :validation_error, :queried_at)
        """, results)
        conn.executemany(
            "UPDATE domains SET scanned_dnssec=1 WHERE domain=?",
            [(r["domain"],) for r in results],
        )


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DNSSEC validation (all DNSLink domains)")
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--qps",     type=int, default=DNS_QPS)
    args = parser.parse_args()

    db.init_db()
    _init_resolvers()

    pending = _fetch_pending()
    print(f"[03] DNSLink domains to validate: {len(pending):,}")
    if not pending:
        print("[03] Nothing pending — run 02_scan_dnslink.py first.")
        return

    delay      = 1.0 / args.qps
    BATCH_SIZE = 50
    batch: list[dict] = []
    counts     = {"full": 0, "partial_no_ds": 0, "partial_no_rrsig": 0,
                  "broken": 0, "none": 0}
    idx = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool, \
         tqdm(total=len(pending), desc="DNSSEC validation", unit="domains") as pbar:

        futures: dict = {}
        for row in pending:
            if _shutdown:
                break
            resolver = _resolvers[idx % len(_resolvers)]
            idx += 1
            fut = pool.submit(validate_domain, row["domain"], resolver)
            futures[fut] = row["domain"]
            time.sleep(delay)

        for fut in as_completed(futures):
            futures.pop(fut)
            try:
                r = fut.result()
            except Exception as e:
                # Shouldn't reach here, but guard anyway
                r = {
                    "domain": "unknown", "has_dnskey": 0, "has_ds": 0,
                    "has_rrsig_txt": 0, "chain_valid": 0, "ad_flag": 0,
                    "dnssec_class": "none", "validation_error": str(e)[:200],
                    "queried_at": datetime.now(timezone.utc).isoformat(),
                }

            counts[r["dnssec_class"]] = counts.get(r["dnssec_class"], 0) + 1
            batch.append(r)

            if len(batch) >= BATCH_SIZE:
                _save_batch(batch)
                batch = []

            pbar.update(1)
            pbar.set_postfix(
                full=counts["full"],
                partial=counts["partial_no_ds"],
                broken=counts["broken"],
                none=counts["none"],
            )

    if batch:
        _save_batch(batch)

    total = sum(counts.values())
    print(f"\n[03] Done — {total:,} domains validated.")
    print(f"     Bucket breakdown:")
    for bucket, n in sorted(counts.items(), key=lambda x: -x[1]):
        pct = n / total * 100 if total else 0
        print(f"       {bucket:<22} {n:>5}  ({pct:.1f}%)")


if __name__ == "__main__":
    main()
