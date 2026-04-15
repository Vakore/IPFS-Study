#!/usr/bin/env python3
"""
04_geo_asn.py  —  IP geolocation, ASN mapping, reverse-DNS, and pinning-service
                   classification for ALL scanned domains, using local MaxMind
                   GeoLite2 databases instead of live API calls.

Why local databases?
────────────────────
  The previous version called ip-api.com for every batch of 100 IPs.  At
  3–4 domains/sec this would take 4+ hours for 50k domains and is fragile
  (connection drops, rate limits).

  MaxMind GeoLite2 .mmdb files are memory-mapped binary trees.  A single
  lookup takes ~10 µs.  50k domains resolve in seconds, not hours, and
  there are zero network calls for geo data.

Setup (one-time — do this before running the script)
─────────────────────────────────────────────────────
  1. Register for a free MaxMind account:
       https://www.maxmind.com/en/geolite2/signup

  2. Generate a license key at:
       Account → Manage License Keys → Generate new license key

  3. Download the two database files — either manually or via this script:

     Auto-download (recommended):
       export MAXMIND_LICENSE_KEY="your_key_here"
       python 04_geo_asn.py --download

     Manual download:
       From https://www.maxmind.com/en/accounts/YOUR_ACCOUNT/geoip/downloads
       download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb, then place them
       in the same directory as this script (or set MMDB_CITY / MMDB_ASN
       in config.py).

  The databases are updated monthly.  Re-run --download at the start of
  each new study run to ensure currency.

Performance
───────────
  IP resolution (dnspython) : ~40 domains/sec (network-bound, unchanged)
  Geo lookup (local mmdb)   : ~50,000 lookups/sec (CPU-bound, no network)
  rDNS (PTR lookup)         : ~10 domains/sec per thread (network-bound)
  Total expected throughput : ~500–2,000 domains/min depending on rDNS

  Use --skip-rdns to skip reverse-DNS if you only need country/ASN data.
  rDNS is used to improve pinning-service detection confidence but is not
  required for the geo sections of the paper.

Usage:
    python 04_geo_asn.py --download          # download mmdb files first
    python 04_geo_asn.py                     # run geo scan
    python 04_geo_asn.py --skip-rdns         # skip PTR lookups (faster)
    python 04_geo_asn.py --workers 50        # more parallel IP resolution
    python 04_geo_asn.py --limit 5000        # process only N domains
"""

import argparse
import os
import signal
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver
import geoip2.database
import geoip2.errors
from tqdm import tqdm

import db
from config import (
    DNS_TIMEOUT, DNS_LIFETIME, RESOLVERS,
    PINNING_SERVICES, CLOUD_PROVIDERS,
)

# ── Database file paths ─────────────────────────────────────────────────────
# Override these in config.py as MMDB_CITY / MMDB_ASN if you store the
# files elsewhere.
_HERE = Path(__file__).parent
try:
    from config import MMDB_CITY  # type: ignore
except ImportError:
    MMDB_CITY = str(_HERE / "GeoLite2-City.mmdb")
try:
    from config import MMDB_ASN   # type: ignore
except ImportError:
    MMDB_ASN  = str(_HERE / "GeoLite2-ASN.mmdb")

# MaxMind download URL template (requires a license key)
_MMDB_DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id={edition}&license_key={key}&suffix=tar.gz"
)

# ── Graceful shutdown ───────────────────────────────────────────────────────
_shutdown = False

def _handle_signal(sig, frame):
    global _shutdown
    print("\n[04] Interrupt — saving progress …")
    _shutdown = True

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ── MaxMind database download ───────────────────────────────────────────────

def download_mmdb(license_key: str):
    """
    Download GeoLite2-City and GeoLite2-ASN mmdb files from MaxMind.
    Requires a free MaxMind license key.
    """
    import tarfile, tempfile

    editions = {
        "GeoLite2-City": MMDB_CITY,
        "GeoLite2-ASN":  MMDB_ASN,
    }

    for edition, dest_path in editions.items():
        url = _MMDB_DOWNLOAD_URL.format(edition=edition, key=license_key)
        print(f"[04] Downloading {edition} …")
        try:
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
                tmp_path = tmp.name
                # Stream download with progress
                with urllib.request.urlopen(url) as resp:
                    total = int(resp.headers.get("Content-Length", 0))
                    downloaded = 0
                    chunk = 65536
                    with tqdm(total=total, unit="B", unit_scale=True,
                              desc=edition) as pbar:
                        while True:
                            data = resp.read(chunk)
                            if not data:
                                break
                            tmp.write(data)
                            downloaded += len(data)
                            pbar.update(len(data))

            # Extract the .mmdb file from the tarball
            with tarfile.open(tmp_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(".mmdb"):
                        member.name = os.path.basename(member.name)
                        tar.extract(member, path=os.path.dirname(dest_path))
                        extracted = os.path.join(
                            os.path.dirname(dest_path), member.name)
                        if extracted != dest_path:
                            os.rename(extracted, dest_path)
                        print(f"[04] Saved → {dest_path}")
                        break

        except Exception as e:
            print(f"[04] ERROR downloading {edition}: {e}", file=sys.stderr)
            print(f"[04] Download manually from:")
            print(f"     https://www.maxmind.com/en/accounts/YOUR_ID/geoip/downloads")
            sys.exit(1)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


def check_mmdb_files() -> bool:
    """Return True if both mmdb files exist and are non-empty."""
    for path in (MMDB_CITY, MMDB_ASN):
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return False
    return True


# ── Local GeoIP readers (opened once, reused across threads) ────────────────
# geoip2 readers are thread-safe for read operations.
_city_reader: geoip2.database.Reader | None = None
_asn_reader:  geoip2.database.Reader | None = None


def _open_readers():
    global _city_reader, _asn_reader
    try:
        _city_reader = geoip2.database.Reader(MMDB_CITY)
        _asn_reader  = geoip2.database.Reader(MMDB_ASN)
    except Exception as e:
        print(f"[04] ERROR opening mmdb files: {e}", file=sys.stderr)
        print(f"[04] Run:  python 04_geo_asn.py --download")
        sys.exit(1)


def _close_readers():
    if _city_reader:
        _city_reader.close()
    if _asn_reader:
        _asn_reader.close()


def lookup_geo(ip: str) -> dict:
    """
    Look up city + ASN data for an IP address using local mmdb files.
    Returns a flat dict with all geo fields.  Never raises — returns empty
    strings on any lookup failure (private IPs, unregistered blocks, etc.).
    """
    result = {
        "country": "", "country_code": "", "region": "", "city": "",
        "asn": "", "asn_name": "", "isp": "", "org": "",
    }
    if not ip:
        return result

    # City / country lookup
    try:
        city = _city_reader.city(ip)
        result["country"]      = city.country.name or ""
        result["country_code"] = city.country.iso_code or ""
        result["region"]       = (city.subdivisions.most_specific.name or "")
        result["city"]         = city.city.name or ""
    except (geoip2.errors.AddressNotFoundError, Exception):
        pass

    # ASN lookup
    try:
        asn = _asn_reader.asn(ip)
        result["asn"]      = f"AS{asn.autonomous_system_number}" if asn.autonomous_system_number else ""
        result["asn_name"] = asn.autonomous_system_organization or ""
        result["isp"]      = result["asn_name"]   # MaxMind ASN db doesn't separate ISP/org
        result["org"]      = result["asn_name"]
    except (geoip2.errors.AddressNotFoundError, Exception):
        pass

    return result


# ── DNS helpers ─────────────────────────────────────────────────────────────
_dns_resolver: dns.resolver.Resolver | None = None


def _init_dns():
    global _dns_resolver
    _dns_resolver = dns.resolver.Resolver(configure=False)
    _dns_resolver.nameservers = RESOLVERS
    _dns_resolver.timeout     = DNS_TIMEOUT
    _dns_resolver.lifetime    = DNS_LIFETIME


def resolve_ip(domain: str) -> str | None:
    """Return the first A record for a domain, or None on failure."""
    try:
        ans = _dns_resolver.resolve(domain, "A", raise_on_no_answer=False)
        if ans.rrset:
            return str(ans.rrset[0])
    except Exception:
        pass
    return None


def rdns_lookup(ip: str) -> str | None:
    """Reverse-DNS PTR lookup. Returns lowercase hostname or None."""
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return None


# ── Pinning / hosting classifier ────────────────────────────────────────────

def classify_provider(asn_name: str, rdns: str | None,
                      response_headers: dict | None = None) -> dict:
    asn_lower  = asn_name.lower()
    rdns_lower = (rdns or "").lower()
    hdrs_lower = {k.lower() for k in (response_headers or {}).keys()}

    signals: list[tuple[str, str]] = []

    for svc, patterns in PINNING_SERVICES.items():
        for pat in patterns["asn"]:
            if pat in asn_lower:
                signals.append((svc, "asn")); break
        for pat in patterns["rdns"]:
            if pat in rdns_lower:
                signals.append((svc, "rdns")); break
        for pat in patterns["headers"]:
            if any(pat in h for h in hdrs_lower):
                signals.append((svc, "header")); break

    if signals:
        top_svc    = signals[0][0]
        methods    = list(dict.fromkeys(m for _, m in signals))
        matching   = [s for s, _ in signals if s == top_svc]
        confidence = "high" if len(matching) >= 2 else "medium"
        return {"detected_service": top_svc, "detection_method": "|".join(methods),
                "confidence": confidence, "is_known_pinning": 1, "is_private_node": 0}

    for provider, patterns in CLOUD_PROVIDERS.items():
        if any(p in asn_lower for p in patterns):
            return {"detected_service": provider, "detection_method": "asn",
                    "confidence": "medium", "is_known_pinning": 0, "is_private_node": 1}

    label = "private_hosted" if rdns_lower and any(
        kw in rdns_lower for kw in ("server","vps","node","host","static")
    ) else "private_residential"
    return {"detected_service": label, "detection_method": "fallthrough",
            "confidence": "low", "is_known_pinning": 0, "is_private_node": 1}


# ── Per-domain worker ────────────────────────────────────────────────────────

def process_domain(domain: str, do_rdns: bool) -> dict:
    """
    Resolve IP → local geo lookup → optional rDNS → classify provider.
    Returns a combined result dict used for both DB tables.
    """
    ts  = datetime.now(timezone.utc).isoformat()
    ip  = resolve_ip(domain)
    geo = lookup_geo(ip) if ip else {
        "country": "", "country_code": "", "region": "", "city": "",
        "asn": "", "asn_name": "", "isp": "", "org": "",
    }
    rdns = rdns_lookup(ip) if (ip and do_rdns) else None
    pin  = classify_provider(geo["asn_name"], rdns)

    return {
        # geo_results columns
        "domain":        domain,
        "ip_address":    ip,
        "rdns_hostname": rdns,
        "country":       geo["country"],
        "country_code":  geo["country_code"],
        "region":        geo["region"],
        "city":          geo["city"],
        "isp":           geo["isp"],
        "org":           geo["org"],
        "asn":           geo["asn"],
        "asn_name":      geo["asn_name"],
        "queried_at":    ts,
        # pinning_detection columns (merged for single pass)
        "detected_service": pin["detected_service"],
        "detection_method": pin["detection_method"],
        "confidence":       pin["confidence"],
        "is_known_pinning": pin["is_known_pinning"],
        "is_private_node":  pin["is_private_node"],
    }


# ── Database helpers ────────────────────────────────────────────────────────

def _fetch_pending(limit: int | None = None) -> list:
    """All DNS-scanned domains not yet geo-located."""
    with db.get_db() as conn:
        sql = """
            SELECT domain FROM domains
            WHERE  scanned_dnslink = 1 AND scanned_geo = 0
            ORDER  BY rank ASC
        """
        if limit:
            sql += f" LIMIT {limit}"
        return conn.execute(sql).fetchall()


def _count_stats() -> tuple[int, int]:
    with db.get_db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM domains WHERE scanned_dnslink=1 AND scanned_geo=0"
        ).fetchone()[0]
        dl = conn.execute(
            """SELECT COUNT(*) FROM domains d
               JOIN dnslink_records dr ON dr.domain=d.domain
               WHERE d.scanned_dnslink=1 AND d.scanned_geo=0"""
        ).fetchone()[0]
    return total, dl


def _save_batch(results: list[dict]):
    geo_rows = [{k: r[k] for k in (
        "domain","ip_address","rdns_hostname","country","country_code",
        "region","city","isp","org","asn","asn_name","queried_at"
    )} for r in results]

    pin_rows = [{
        "domain":           r["domain"],
        "ip_address":       r["ip_address"],
        "detected_service": r["detected_service"],
        "detection_method": r["detection_method"],
        "confidence":       r["confidence"],
        "is_known_pinning": r["is_known_pinning"],
        "is_private_node":  r["is_private_node"],
        "checked_at":       r["queried_at"],
    } for r in results]

    with db.get_db() as conn:
        conn.executemany("""
            INSERT INTO geo_results
              (domain, ip_address, rdns_hostname, country, country_code,
               region, city, isp, org, asn, asn_name, queried_at)
            VALUES
              (:domain, :ip_address, :rdns_hostname, :country, :country_code,
               :region, :city, :isp, :org, :asn, :asn_name, :queried_at)
        """, geo_rows)
        conn.executemany("""
            INSERT INTO pinning_detection
              (domain, ip_address, detected_service, detection_method,
               confidence, is_known_pinning, is_private_node, checked_at)
            VALUES
              (:domain, :ip_address, :detected_service, :detection_method,
               :confidence, :is_known_pinning, :is_private_node, :checked_at)
        """, pin_rows)
        conn.executemany(
            "UPDATE domains SET scanned_geo=1 WHERE domain=?",
            [(r["domain"],) for r in results],
        )


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Geo / ASN / rDNS / pinning — local mmdb, no network geo calls")
    parser.add_argument("--download",   action="store_true",
                        help="Download GeoLite2 mmdb files from MaxMind then exit")
    parser.add_argument("--license-key", type=str,
                        default=os.environ.get("MAXMIND_LICENSE_KEY", ""),
                        help="MaxMind license key (or set MAXMIND_LICENSE_KEY env var)")
    parser.add_argument("--workers",    type=int, default=50,
                        help="Concurrent threads for IP resolution + rDNS (default 50)")
    parser.add_argument("--skip-rdns",  action="store_true",
                        help="Skip reverse-DNS PTR lookups (faster, lower pinning confidence)")
    parser.add_argument("--limit",      type=int, default=0,
                        help="Process only N pending domains (0 = all)")
    args = parser.parse_args()

    # ── Download mode ───────────────────────────────────────────────────────
    if args.download:
        key = args.license_key
        if not key:
            print("[04] ERROR: provide --license-key or set MAXMIND_LICENSE_KEY")
            print("[04] Get a free key at: https://www.maxmind.com/en/geolite2/signup")
            sys.exit(1)
        download_mmdb(key)
        print("[04] Download complete.  Run without --download to start scanning.")
        return

    # ── Pre-flight: check mmdb files exist ─────────────────────────────────
    if not check_mmdb_files():
        print("[04] ERROR: MaxMind mmdb files not found.")
        print(f"[04]   Expected: {MMDB_CITY}")
        print(f"[04]             {MMDB_ASN}")
        print("[04]")
        print("[04] Option 1 — auto-download (free MaxMind account required):")
        print("[04]   export MAXMIND_LICENSE_KEY=your_key_here")
        print("[04]   python 04_geo_asn.py --download")
        print("[04]")
        print("[04] Option 2 — manual download:")
        print("[04]   1. Register free at https://www.maxmind.com/en/geolite2/signup")
        print("[04]   2. Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb")
        print("[04]   3. Place both files in this directory")
        sys.exit(1)

    db.init_db()
    _init_dns()
    _open_readers()

    # Print mmdb metadata
    print(f"[04] City DB  : {MMDB_CITY}")
    print(f"[04]   build  : {_city_reader.metadata().build_epoch}")
    print(f"[04] ASN DB   : {MMDB_ASN}")
    print(f"[04]   build  : {_asn_reader.metadata().build_epoch}")

    total_pending, with_dl = _count_stats()
    print(f"\n[04] Domains pending geo scan : {total_pending:,}")
    print(f"[04]   with DNSLink           : {with_dl:,}")
    print(f"[04]   without DNSLink        : {total_pending - with_dl:,}")
    if args.skip_rdns:
        print(f"[04] rDNS : SKIPPED (--skip-rdns)")
    else:
        print(f"[04] rDNS : enabled (use --skip-rdns to go faster)")

    if not total_pending:
        print("[04] Nothing to do — run 02_scan_dnslink.py first.")
        _close_readers()
        return

    pending = _fetch_pending(args.limit or None)
    print(f"[04] Processing {len(pending):,} domains with {args.workers} workers …\n")

    BATCH_SIZE = 500
    buf: list[dict] = []
    resolved = failed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool, \
         tqdm(total=len(pending), desc="Geo scan", unit="domains",
              dynamic_ncols=True) as pbar:

        futures = {
            pool.submit(process_domain, row["domain"], not args.skip_rdns): row["domain"]
            for row in pending
            if not _shutdown
        }

        for fut in as_completed(futures):
            if _shutdown:
                break
            domain = futures.pop(fut)
            try:
                result = fut.result()
            except Exception as e:
                ts = datetime.now(timezone.utc).isoformat()
                result = {
                    "domain": domain, "ip_address": None, "rdns_hostname": None,
                    "country": "", "country_code": "", "region": "", "city": "",
                    "isp": "", "org": "", "asn": "", "asn_name": "",
                    "queried_at": ts, "detected_service": "error",
                    "detection_method": "error", "confidence": "low",
                    "is_known_pinning": 0, "is_private_node": 0,
                }
                failed += 1

            if result["ip_address"]:
                resolved += 1

            buf.append(result)
            if len(buf) >= BATCH_SIZE:
                _save_batch(buf)
                buf = []

            pbar.update(1)
            pbar.set_postfix(resolved=resolved, failed=failed, refresh=False)

    if buf:
        _save_batch(buf)

    _close_readers()

    total = len(pending)
    print(f"\n[04] Done — {total:,} domains processed.")
    print(f"     IP resolved  : {resolved:,} ({resolved/total*100:.1f}%)")
    print(f"     No IP found  : {total - resolved:,}")
    print(f"     Errors       : {failed:,}")
    print(f"\n[04] Run 07_analyze.py --section geo  for country breakdown.")
    print(f"[04] Run 07_analyze.py --section asn  for provider breakdown.")


if __name__ == "__main__":
    main()