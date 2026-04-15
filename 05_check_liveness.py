#!/usr/bin/env python3
"""
05_check_liveness.py  —  CID gateway liveness, Kubo agent version, TLS
                          certificate analysis, and domain HTTP probe.

Scope change from v1
────────────────────
  Phase 1 (CID gateway probes + Kubo agent version)
    Unchanged — only runs on /ipfs/ CIDs from dnslink_records.
    These checks are inherently IPFS-specific.

  Phase 2 (TLS certificate + domain HTTP probe)
    Now runs on ALL scanned domains, not just DNSLink ones.
    Every domain in the study gets:
      • TLS cert validity, issuer, days-to-expiry
      • Plain HTTP status after redirects
      • Whether the final URL is an IPFS gateway

    This gives the paper a full-corpus TLS baseline so we can answer:
      "How does TLS hygiene of IPFS-adopting domains compare to the
       general top-N population?"

    Kubo agent version detection from gateway response headers remains
    DNSLink-scoped (non-IPFS domains won't serve Kubo headers).

Usage:
    python 05_check_liveness.py
    python 05_check_liveness.py --workers 20
    python 05_check_liveness.py --skip-tls       # skip Phase 2
    python 05_check_liveness.py --skip-liveness  # skip Phase 1
"""

import argparse
import re
import signal
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
import urllib3
from tqdm import tqdm

import db
from config import (
    IPFS_GATEWAYS, IPFS_RPS, GATEWAY_TIMEOUT,
    KUBO_MINIMUM_VERSION, TLS_TIMEOUT, HTTP_TIMEOUT,
    CERT_WARN_DAYS, PINNING_SERVICES,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Graceful shutdown ───────────────────────────────────────────────────────
_shutdown = False

def _handle_signal(sig, frame):
    global _shutdown
    print("\n[05] Interrupt — saving progress …")
    _shutdown = True

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── Thread-local HTTP session ───────────────────────────────────────────────
_tl = threading.local()

def _session() -> requests.Session:
    if not hasattr(_tl, "s"):
        s = requests.Session()
        s.headers["User-Agent"] = "IPFS-FieldStudy/2.0 (academic; cs780)"
        _tl.s = s
    return _tl.s


# ── Agent version parsing ───────────────────────────────────────────────────
_AGENT_RE = re.compile(
    r"(?:kubo|go-ipfs)[/ ](\d+)\.(\d+)\.(\d+)", re.IGNORECASE
)
_SRC_HEADERS = ["server", "x-ipfs-version", "via", "x-powered-by"]


def parse_agent(headers: dict) -> dict | None:
    """Scan response headers for a Kubo/go-ipfs version string."""
    for src in _SRC_HEADERS:
        val = headers.get(src, "")
        m   = _AGENT_RE.search(val)
        if m:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            return {
                "raw_agent":     m.group(0),
                "kubo_version":  f"{major}.{minor}.{patch}",
                "version_major": major,
                "version_minor": minor,
                "version_patch": patch,
                "is_outdated":   int((major, minor, patch) < KUBO_MINIMUM_VERSION),
                "detection_src": src,
            }
    return None


# ── Pinning-service header check ────────────────────────────────────────────

def detect_pinning_from_headers(headers: dict) -> str | None:
    hdrs_lower = {k.lower(): v for k, v in headers.items()}
    for svc, patterns in PINNING_SERVICES.items():
        for pat in patterns["headers"]:
            if any(pat in h for h in hdrs_lower):
                return svc
    return None


# ── Phase 1: CID gateway probe ───────────────────────────────────────────────
# Only runs on domains that have an /ipfs/ CID in dnslink_records.

def probe_cid(domain: str, cid: str, gateway: str) -> tuple[dict, dict | None, str | None]:
    """HEAD the CID via one gateway. Returns (liveness_row, agent_row, pinning_svc)."""
    url = f"{gateway.rstrip('/')}/{cid}"
    live_row = {
        "domain": domain, "cid": cid, "gateway": gateway,
        "http_status": None, "content_type": None, "content_length": None,
        "response_ms": None, "is_live": 0, "error": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    agent_row   = None
    pinning_svc = None

    t0 = time.perf_counter()
    try:
        resp = _session().head(
            url, timeout=GATEWAY_TIMEOUT, allow_redirects=True, verify=True,
        )
        ms = (time.perf_counter() - t0) * 1000
        live_row.update({
            "http_status":  resp.status_code,
            "content_type": resp.headers.get("Content-Type", "")[:120],
            "response_ms":  round(ms, 1),
            "is_live":      int(resp.status_code in range(200, 400)),
        })
        cl = resp.headers.get("Content-Length")
        live_row["content_length"] = int(cl) if cl and cl.isdigit() else None

        av = parse_agent(dict(resp.headers))
        if av:
            agent_row = {**av,
                "domain": domain, "gateway": gateway,
                "checked_at": live_row["checked_at"],
            }
        pinning_svc = detect_pinning_from_headers(dict(resp.headers))

    except requests.exceptions.Timeout:
        live_row["error"] = "timeout"
    except requests.exceptions.SSLError as e:
        live_row["error"] = f"ssl:{str(e)[:60]}"
    except requests.exceptions.ConnectionError as e:
        live_row["error"] = f"conn:{str(e)[:60]}"
    except Exception as e:
        live_row["error"] = str(e)[:100]

    return live_row, agent_row, pinning_svc


# ── Phase 2: TLS certificate + domain HTTP probe ─────────────────────────────
# Runs on ALL scanned domains (with and without DNSLink).

def check_tls(domain: str) -> dict:
    """
    Open a real SSL socket to port 443 and read the peer certificate.
    Then issue a plain HTTP GET (follows redirects) to record the final
    status and whether the domain already points to an IPFS gateway.
    """
    result = {
        "domain": domain, "cert_valid": None,
        "cert_issuer_org": None, "cert_subject_cn": None,
        "cert_expiry_iso": None, "cert_days_remaining": None,
        "cert_is_expired": 0, "cert_expiring_soon": 0, "cert_error": None,
        "domain_http_status": None,
        "domain_redirects_to_ipfs": 0,
        "domain_final_url": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=TLS_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        subject = dict(x[0] for x in cert.get("subject", []))
        expiry  = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days    = (expiry.replace(tzinfo=timezone.utc)
                   - datetime.now(timezone.utc)).days

        result.update({
            "cert_valid":         1,
            "cert_issuer_org":    issuer.get("organizationName", "")[:120],
            "cert_subject_cn":    subject.get("commonName",      "")[:120],
            "cert_expiry_iso":    expiry.isoformat(),
            "cert_days_remaining": days,
            "cert_is_expired":    int(days < 0),
            "cert_expiring_soon": int(0 <= days < CERT_WARN_DAYS),
        })
    except ssl.SSLCertVerificationError as e:
        result.update({"cert_valid": 0, "cert_error": f"invalid:{str(e)[:80]}"})
    except (socket.timeout, TimeoutError):
        result["cert_error"] = "timeout"
    except ConnectionRefusedError:
        result["cert_error"] = "refused"
    except OSError as e:
        result["cert_error"] = str(e)[:80]
    except Exception as e:
        result["cert_error"] = str(e)[:80]

    # HTTP probe — try HTTPS first, fall back to HTTP
    for scheme in ("https", "http"):
        try:
            r = _session().get(
                f"{scheme}://{domain}",
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                stream=True,
            )
            r.close()
            final = r.url
            result.update({
                "domain_http_status": r.status_code,
                "domain_redirects_to_ipfs": int(
                    "/ipfs/" in final or "dnslink" in final.lower()
                    or any(gw.split("/ipfs/")[0] in final for gw in IPFS_GATEWAYS)
                ),
                "domain_final_url": final[:300],
            })
            break
        except Exception:
            continue

    return result


# ── Database helpers ────────────────────────────────────────────────────────

def _fetch_pending_cids() -> list:
    """DNSLink /ipfs/ domains not yet liveness-checked — Phase 1 scope."""
    with db.get_db() as conn:
        return conn.execute("""
            SELECT DISTINCT dr.domain, dr.cid
            FROM   dnslink_records dr
            JOIN   domains d ON d.domain = dr.domain
            WHERE  dr.link_type = 'ipfs' AND dr.cid IS NOT NULL
              AND  d.scanned_live = 0
            ORDER  BY d.rank ASC
        """).fetchall()


def _fetch_pending_tls() -> list:
    """
    ALL scanned domains not yet TLS-checked — Phase 2 scope.
    No JOIN on dnslink_records: every domain gets a TLS result row.
    """
    with db.get_db() as conn:
        return conn.execute("""
            SELECT domain
            FROM   domains
            WHERE  scanned_dnslink = 1   -- was DNS-scanned (by script 02)
              AND  scanned_tls     = 0
            ORDER  BY rank ASC
        """).fetchall()


def _count_tls_pending() -> tuple[int, int]:
    """Return (total_pending_tls, pending_with_dnslink) for info display."""
    with db.get_db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM domains WHERE scanned_dnslink=1 AND scanned_tls=0"
        ).fetchone()[0]
        with_dl = conn.execute(
            """SELECT COUNT(*) FROM domains d
               JOIN dnslink_records dr ON dr.domain=d.domain
               WHERE d.scanned_dnslink=1 AND d.scanned_tls=0"""
        ).fetchone()[0]
    return total, with_dl


def _save_liveness_batch(live_rows, agent_rows, pinning_updates, domains):
    with db.get_db() as conn:
        conn.executemany("""
            INSERT INTO liveness_results
              (domain, cid, gateway, http_status, content_type,
               content_length, response_ms, is_live, error, checked_at)
            VALUES
              (:domain, :cid, :gateway, :http_status, :content_type,
               :content_length, :response_ms, :is_live, :error, :checked_at)
        """, live_rows)
        if agent_rows:
            conn.executemany("""
                INSERT INTO agent_versions
                  (domain, gateway, raw_agent, kubo_version,
                   version_major, version_minor, version_patch,
                   is_outdated, detection_src, checked_at)
                VALUES
                  (:domain, :gateway, :raw_agent, :kubo_version,
                   :version_major, :version_minor, :version_patch,
                   :is_outdated, :detection_src, :checked_at)
            """, agent_rows)
        for domain, svc in pinning_updates:
            conn.execute("""
                UPDATE pinning_detection
                SET    detected_service = ?,
                       detection_method = detection_method || '|header',
                       confidence = 'high', is_known_pinning = 1
                WHERE  domain = ?
                  AND  (detected_service = ? OR confidence != 'high')
            """, (svc, domain, svc))
        conn.executemany(
            "UPDATE domains SET scanned_live=1 WHERE domain=?",
            [(d,) for d in set(domains)],
        )


def _save_tls_batch(rows: list[dict], domains: list[str]):
    with db.get_db() as conn:
        conn.executemany("""
            INSERT INTO tls_results
              (domain, cert_valid, cert_issuer_org, cert_subject_cn,
               cert_expiry_iso, cert_days_remaining, cert_is_expired,
               cert_expiring_soon, cert_error,
               domain_http_status, domain_redirects_to_ipfs, domain_final_url,
               checked_at)
            VALUES
              (:domain, :cert_valid, :cert_issuer_org, :cert_subject_cn,
               :cert_expiry_iso, :cert_days_remaining, :cert_is_expired,
               :cert_expiring_soon, :cert_error,
               :domain_http_status, :domain_redirects_to_ipfs, :domain_final_url,
               :checked_at)
        """, rows)
        conn.executemany(
            "UPDATE domains SET scanned_tls=1 WHERE domain=?",
            [(d,) for d in set(domains)],
        )


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CID liveness (DNSLink only) + TLS/HTTP (all domains)")
    parser.add_argument("--workers",        type=int,   default=15)
    parser.add_argument("--rps",            type=float, default=IPFS_RPS)
    parser.add_argument("--gateways",       nargs="*",
                        help="Override gateway list")
    parser.add_argument("--skip-liveness",  action="store_true",
                        help="Skip Phase 1 (CID gateway probes)")
    parser.add_argument("--skip-tls",       action="store_true",
                        help="Skip Phase 2 (TLS + domain HTTP)")
    args = parser.parse_args()

    gateways = args.gateways or IPFS_GATEWAYS
    db.init_db()

    # ── Phase 1: CID liveness + Kubo agent version ─────────────────────────
    if not args.skip_liveness:
        cid_pending = _fetch_pending_cids()
        n_work      = len(cid_pending) * len(gateways)
        print(f"\n[05] Phase 1 — CID liveness (DNSLink domains only)")
        print(f"[05] {len(cid_pending):,} CIDs × {len(gateways)} gateways"
              f" = {n_work:,} requests")
        print(f"[05] Gateways: {gateways}")

        delay    = 1.0 / (args.rps * len(gateways))
        BATCH    = args.workers * 6
        live_buf, agent_buf, pin_updates, dom_buf = [], [], [], []
        live_count = 0

        work = [(r["domain"], r["cid"], gw)
                for r in cid_pending for gw in gateways]

        with ThreadPoolExecutor(max_workers=args.workers) as pool, \
             tqdm(total=len(work), desc="CID liveness", unit="probes") as pbar:

            futures = {}
            for domain, cid, gw in work:
                if _shutdown:
                    break
                fut = pool.submit(probe_cid, domain, cid, gw)
                futures[fut] = domain
                time.sleep(delay)

            for fut in as_completed(futures):
                domain = futures.pop(fut)
                try:
                    live_row, agent_row, pin_svc = fut.result()
                except Exception as e:
                    live_row  = {
                        "domain": domain, "cid": None, "gateway": "?",
                        "http_status": None, "content_type": None,
                        "content_length": None, "response_ms": None,
                        "is_live": 0, "error": str(e)[:80],
                        "checked_at": datetime.now(timezone.utc).isoformat(),
                    }
                    agent_row, pin_svc = None, None

                live_buf.append(live_row)
                dom_buf.append(domain)
                if agent_row:
                    agent_buf.append(agent_row)
                if pin_svc:
                    pin_updates.append((domain, pin_svc))
                if live_row["is_live"]:
                    live_count += 1

                if len(live_buf) >= BATCH:
                    _save_liveness_batch(live_buf, agent_buf, pin_updates, dom_buf)
                    live_buf, agent_buf, pin_updates, dom_buf = [], [], [], []

                pbar.update(1)
                pbar.set_postfix(live=live_count)

        if live_buf:
            _save_liveness_batch(live_buf, agent_buf, pin_updates, dom_buf)

        print(f"\n[05] Phase 1 done — {live_count:,}/{n_work:,} live probes.")
    else:
        print("[05] Phase 1 skipped (--skip-liveness).")

    # ── Phase 2: TLS + domain HTTP — ALL scanned domains ───────────────────
    if not args.skip_tls:
        tls_pending = _fetch_pending_tls()
        total_tls, with_dl = _count_tls_pending()

        # _fetch_pending_tls was already called above; reuse count info
        total_tls = len(tls_pending)
        with_dl_count = sum(
            1 for r in tls_pending
        )  # we'll compute from DB instead
        print(f"\n[05] Phase 2 — TLS certificate + domain HTTP (ALL scanned domains)")
        print(f"[05] {total_tls:,} domains to check")
        print(f"[05] (includes domains without DNSLink — gives full corpus baseline)")

        BATCH    = 50
        tls_buf: list[dict] = []
        tls_doms: list[str] = []
        expired = expiring = no_https = 0

        with ThreadPoolExecutor(max_workers=args.workers) as pool, \
             tqdm(total=len(tls_pending), desc="TLS + HTTP", unit="domains") as pbar:

            futures = {}
            for row in tls_pending:
                if _shutdown:
                    break
                fut = pool.submit(check_tls, row["domain"])
                futures[fut] = row["domain"]

            for fut in as_completed(futures):
                domain = futures.pop(fut)
                try:
                    r = fut.result()
                except Exception as e:
                    r = {
                        "domain": domain, "cert_valid": None,
                        "cert_issuer_org": None, "cert_subject_cn": None,
                        "cert_expiry_iso": None, "cert_days_remaining": None,
                        "cert_is_expired": 0, "cert_expiring_soon": 0,
                        "cert_error": str(e)[:80],
                        "domain_http_status": None,
                        "domain_redirects_to_ipfs": 0, "domain_final_url": None,
                        "checked_at": datetime.now(timezone.utc).isoformat(),
                    }

                tls_buf.append(r)
                tls_doms.append(domain)
                if r["cert_is_expired"]:
                    expired += 1
                if r["cert_expiring_soon"]:
                    expiring += 1
                if r["cert_valid"] is None:
                    no_https += 1

                if len(tls_buf) >= BATCH:
                    _save_tls_batch(tls_buf, tls_doms)
                    tls_buf, tls_doms = [], []

                pbar.update(1)
                pbar.set_postfix(expired=expired, expiring=expiring, no_https=no_https)

        if tls_buf:
            _save_tls_batch(tls_buf, tls_doms)

        print(f"\n[05] Phase 2 done.")
        print(f"     No HTTPS (port 443 refused)  : {no_https:,}")
        print(f"     Expired certs                : {expired:,}")
        print(f"     Expiring within {CERT_WARN_DAYS} days      : {expiring:,}")
        print(f"\n[05] Run 07_analyze.py --section tls for full breakdown.")
    else:
        print("[05] Phase 2 skipped (--skip-tls).")


if __name__ == "__main__":
    main()
