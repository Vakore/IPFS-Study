#!/usr/bin/env python3
"""
07_analyze.py  —  Full analysis report across all 16 sections.

Key change from v1
──────────────────
  Sections D (geo), E (ASN), F (pinning), and H (TLS) now show two columns
  side-by-side wherever it's meaningful:
    • ALL domains   — every domain that was DNS-scanned
    • DNSLink only  — the IPFS-using subset

  This lets the paper answer: "Is IPFS infrastructure more/less centralised
  than the general web?  Are DNSLink sites TLS-healthier or worse?"

  Sections that are inherently DNSLink-scoped (C DNSSEC, I liveness,
  J DAG, K providers, L IPNS, O ENS) remain unchanged.

Usage:
    python 07_analyze.py                     # all sections
    python 07_analyze.py --section geo       # single section
    python 07_analyze.py --csv               # write CSVs to analysis_output/
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime

try:
    import pandas as pd
    from tabulate import tabulate
except ImportError:
    sys.exit("Run:  pip install pandas tabulate")

from config import DB_PATH, ANALYSIS_OUTPUT_DIR


# ── Helpers ─────────────────────────────────────────────────────────────────

def _q(sql: str, params=()) -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    df = pd.read_sql_query(sql, conn, params=params)
    conn.close()
    return df


def _scalar(sql: str) -> int | float:
    conn = sqlite3.connect(DB_PATH)
    val = conn.execute(sql).fetchone()[0] or 0
    conn.close()
    return val


def _pct(part, total, decimals: int = 1) -> str:
    if not total:
        return "—"
    return f"{part / total * 100:.{decimals}f}%"


def _hdr(title: str):
    bar = "═" * 70
    print(f"\n{bar}\n  {title}\n{bar}")


def _tbl(df: pd.DataFrame, fmt: str = "rounded_outline"):
    print(tabulate(df, headers="keys", tablefmt=fmt,
                   showindex=False, floatfmt=".1f"))


def _csv(df: pd.DataFrame, name: str, save: bool):
    if not save:
        return
    os.makedirs(ANALYSIS_OUTPUT_DIR, exist_ok=True)
    p = os.path.join(ANALYSIS_OUTPUT_DIR, f"{name}.csv")
    df.to_csv(p, index=False)
    print(f"  → {p}")


def _note(text: str):
    """Print a soft annotation line."""
    print(f"  ╌ {text}")


# =============================================================================
# A. Overview
# =============================================================================
def section_overview(save: bool):
    _hdr("A. OVERVIEW")
    c = _q("""
        SELECT COUNT(*) AS total,
               SUM(scanned_dnslink)    AS s_dns,
               SUM(scanned_dnssec)     AS s_dnssec,
               SUM(scanned_geo)        AS s_geo,
               SUM(scanned_live)       AS s_live,
               SUM(scanned_tls)        AS s_tls,
               SUM(scanned_dag)        AS s_dag,
               SUM(scanned_providers)  AS s_prov,
               SUM(scanned_ipns)       AS s_ipns,
               SUM(scanned_ens)        AS s_ens
        FROM domains
    """).iloc[0]
    tot = int(c["total"]) or 1
    dl  = _scalar("SELECT COUNT(DISTINCT domain) FROM dnslink_records")

    rows = [
        ["Total domains imported",          f"{tot:,}",                   ""],
        ["  DNS-scanned (script 02)",        f"{int(c['s_dns']):,}",       _pct(c['s_dns'],  tot)],
        ["    ↳ have DNSLink record",        f"{dl:,}",                    _pct(dl,           int(c['s_dns']))],
        ["    ↳ lack DNSLink record",        f"{int(c['s_dns'])-dl:,}",    ""],
        ["  DNSSEC-validated (DNSLink only)",f"{int(c['s_dnssec']):,}",    ""],
        ["  Geo-located (all domains)",      f"{int(c['s_geo']):,}",       _pct(c['s_geo'],  int(c['s_dns']))],
        ["  Liveness-checked (DNSLink CIDs)",f"{int(c['s_live']):,}",      ""],
        ["  TLS-checked (all domains)",      f"{int(c['s_tls']):,}",       _pct(c['s_tls'],  int(c['s_dns']))],
        ["  DAG-queried (Kubo RPC)",         f"{int(c['s_dag']):,}",       ""],
        ["  Providers-queried (Kubo RPC)",   f"{int(c['s_prov']):,}",      ""],
        ["  IPNS keys classified",           f"{int(c['s_ipns']):,}",      ""],
        ["  ENS cross-referenced",           f"{int(c['s_ens']):,}",       ""],
    ]
    df = pd.DataFrame(rows, columns=["Metric", "Count", "% of scanned"])
    _tbl(df)
    _csv(df, "A_overview", save)


# =============================================================================
# B. DNSLink record types
# =============================================================================
def section_dnslink(save: bool):
    _hdr("B. DNSLINK RECORD TYPES")
    df = _q("""
        SELECT link_type,
               COUNT(DISTINCT domain) AS unique_domains,
               COUNT(*)               AS total_records,
               ROUND(AVG(ttl),0)      AS avg_ttl_s,
               MIN(ttl)               AS min_ttl_s,
               MAX(ttl)               AS max_ttl_s
        FROM dnslink_records
        GROUP BY link_type ORDER BY unique_domains DESC
    """)
    _tbl(df)
    _csv(df, "B_dnslink_types", save)

    ttl = _q("""
        SELECT CASE
            WHEN ttl < 300    THEN '<5 min'
            WHEN ttl < 3600   THEN '5 min–1 hr'
            WHEN ttl < 86400  THEN '1 hr–1 day'
            WHEN ttl < 604800 THEN '1 day–1 wk'
            ELSE                   '>1 wk'
        END AS ttl_bucket,
        COUNT(DISTINCT domain) AS domains
        FROM dnslink_records GROUP BY ttl_bucket ORDER BY MIN(ttl)
    """)
    print("\n  TTL distribution:")
    _tbl(ttl)
    _csv(ttl, "B_ttl_distribution", save)


# =============================================================================
# C. DNSSEC — DNSLink domains only
# =============================================================================
def section_dnssec(save: bool):
    _hdr("C. DNSSEC VALIDATION — 5-BUCKET BREAKDOWN  (DNSLink domains only)")
    df = _q("""
        SELECT dnssec_class,
               COUNT(*) AS domains,
               ROUND(COUNT(*)*100.0/SUM(COUNT(*)) OVER(),1) AS pct
        FROM dnssec_results
        GROUP BY dnssec_class
        ORDER BY CASE dnssec_class
            WHEN 'full' THEN 1 WHEN 'partial_no_ds' THEN 2
            WHEN 'partial_no_rrsig' THEN 3 WHEN 'broken' THEN 4 ELSE 5 END
    """)
    if df.empty:
        print("  No data — run 03_validate_dnssec.py first.")
        return
    _tbl(df)
    _csv(df, "C_dnssec_buckets", save)

    checks = _q("""
        SELECT COUNT(*) AS total,
               SUM(has_dnskey)    AS dnskey,
               SUM(has_ds)        AS ds,
               SUM(has_rrsig_txt) AS rrsig,
               SUM(ad_flag)       AS ad,
               SUM(chain_valid)   AS chain
        FROM dnssec_results
    """).iloc[0]
    tot = int(checks["total"]) or 1
    print(f"\n  Individual check rates (of {tot:,} DNSLink domains):")
    rows2 = [
        ["DNSKEY at apex",           int(checks["dnskey"]), _pct(checks["dnskey"], tot)],
        ["DS at parent",             int(checks["ds"]),     _pct(checks["ds"],     tot)],
        ["RRSIG on _dnslink TXT",    int(checks["rrsig"]),  _pct(checks["rrsig"],  tot)],
        ["AD flag (resolver valid.)",int(checks["ad"]),     _pct(checks["ad"],     tot)],
        ["Full chain valid",         int(checks["chain"]),  _pct(checks["chain"],  tot)],
    ]
    _tbl(pd.DataFrame(rows2, columns=["Check", "Count", "%"]))

    errs = _q("""
        SELECT validation_error, COUNT(*) n FROM dnssec_results
        WHERE validation_error IS NOT NULL AND validation_error != ''
        GROUP BY validation_error ORDER BY n DESC LIMIT 8
    """)
    if not errs.empty:
        print("\n  Top validation errors:")
        _tbl(errs)
        _csv(errs, "C_dnssec_errors", save)


# =============================================================================
# D. Geographic distribution — ALL domains vs DNSLink subset
# =============================================================================
def section_geo(save: bool, top_n: int = 20):
    _hdr("D. GEOGRAPHIC DISTRIBUTION  (all domains vs DNSLink subset)")

    # All geo-located domains, top countries
    all_df = _q(f"""
        SELECT COALESCE(NULLIF(g.country,''),'Unknown') AS country,
               g.country_code,
               COUNT(DISTINCT g.domain) AS all_domains
        FROM geo_results g
        WHERE g.ip_address IS NOT NULL
        GROUP BY g.country, g.country_code
        ORDER BY all_domains DESC LIMIT {top_n}
    """)

    if all_df.empty:
        print("  No data — run 04_geo_asn.py first.")
        return

    # DNSLink subset
    dl_df = _q(f"""
        SELECT COALESCE(NULLIF(g.country,''),'Unknown') AS country,
               g.country_code,
               COUNT(DISTINCT g.domain) AS dnslink_domains
        FROM geo_results g
        JOIN dnslink_records dr ON dr.domain = g.domain
        WHERE g.ip_address IS NOT NULL
        GROUP BY g.country, g.country_code
        ORDER BY dnslink_domains DESC LIMIT {top_n}
    """)

    merged = all_df.merge(dl_df, on=["country","country_code"], how="left")
    merged["dnslink_domains"] = merged["dnslink_domains"].fillna(0).astype(int)

    tot_all = merged["all_domains"].sum()
    tot_dl  = merged["dnslink_domains"].sum()
    merged["all_%"]      = merged["all_domains"].map(lambda x: _pct(x, tot_all))
    merged["dnslink_%"]  = merged["dnslink_domains"].map(lambda x: _pct(x, tot_dl) if tot_dl else "—")

    _tbl(merged[["country","country_code","all_domains","all_%","dnslink_domains","dnslink_%"]])
    _csv(merged, "D_by_country", save)

    top3_all = merged.head(3)["all_domains"].sum()
    top3_dl  = merged.sort_values("dnslink_domains", ascending=False).head(3)["dnslink_domains"].sum()
    print(f"\n  Top-3 country share — all domains : {_pct(top3_all, tot_all)}")
    print(f"  Top-3 country share — DNSLink     : {_pct(top3_dl, tot_dl)}")


# =============================================================================
# E. ASN / Hosting provider — ALL domains vs DNSLink subset
# =============================================================================
def section_asn(save: bool, top_n: int = 20):
    _hdr("E. TOP HOSTING PROVIDERS (ASN)  (all domains vs DNSLink subset)")

    all_df = _q(f"""
        SELECT COALESCE(NULLIF(g.asn,''),'?')      AS asn,
               COALESCE(NULLIF(g.asn_name,''),'?') AS provider,
               COUNT(DISTINCT g.domain) AS all_domains
        FROM geo_results g
        WHERE g.ip_address IS NOT NULL
        GROUP BY g.asn, g.asn_name
        ORDER BY all_domains DESC LIMIT {top_n}
    """)
    if all_df.empty:
        print("  No data — run 04_geo_asn.py first.")
        return

    dl_df = _q(f"""
        SELECT COALESCE(NULLIF(g.asn,''),'?')      AS asn,
               COUNT(DISTINCT g.domain) AS dnslink_domains
        FROM geo_results g
        JOIN dnslink_records dr ON dr.domain = g.domain
        WHERE g.ip_address IS NOT NULL
        GROUP BY g.asn
        ORDER BY dnslink_domains DESC LIMIT {top_n}
    """)

    merged = all_df.merge(dl_df, on="asn", how="left")
    merged["dnslink_domains"] = merged["dnslink_domains"].fillna(0).astype(int)

    tot_all = merged["all_domains"].sum()
    tot_dl  = merged["dnslink_domains"].sum()
    merged["all_%"]     = merged["all_domains"].map(lambda x: _pct(x, tot_all))
    merged["dnslink_%"] = merged["dnslink_domains"].map(lambda x: _pct(x, tot_dl) if tot_dl else "—")

    _tbl(merged[["asn","provider","all_domains","all_%","dnslink_domains","dnslink_%"]])
    _csv(merged, "E_by_asn", save)

    top3_all = merged.head(3)["all_domains"].sum()
    top3_dl  = merged.sort_values("dnslink_domains", ascending=False).head(3)["dnslink_domains"].sum()
    print(f"\n  Top-3 ASN share — all domains : {_pct(top3_all, tot_all)}")
    print(f"  Top-3 ASN share — DNSLink     : {_pct(top3_dl,  tot_dl)}")
    _note("High DNSLink concentration suggests 'decentralised' content depends heavily on a few hosts.")


# =============================================================================
# F. Pinning service classification — ALL domains vs DNSLink subset
# =============================================================================
def section_pinning(save: bool):
    _hdr("F. HOSTING CLASSIFICATION  (all domains vs DNSLink subset)")

    all_df = _q("""
        SELECT detected_service, is_known_pinning,
               COUNT(*) AS all_domains
        FROM pinning_detection
        GROUP BY detected_service, is_known_pinning
        ORDER BY all_domains DESC
    """)
    if all_df.empty:
        print("  No data — run 04_geo_asn.py first.")
        return

    dl_df = _q("""
        SELECT pd.detected_service,
               COUNT(DISTINCT pd.domain) AS dnslink_domains
        FROM pinning_detection pd
        JOIN dnslink_records dr ON dr.domain = pd.domain
        GROUP BY pd.detected_service
    """)

    merged = all_df.merge(dl_df, on="detected_service", how="left")
    merged["dnslink_domains"] = merged["dnslink_domains"].fillna(0).astype(int)

    tot_all = merged["all_domains"].sum()
    tot_dl  = merged["dnslink_domains"].sum()
    merged["all_%"]     = merged["all_domains"].map(lambda x: _pct(x, tot_all))
    merged["dnslink_%"] = merged["dnslink_domains"].map(lambda x: _pct(x, tot_dl) if tot_dl else "—")

    _tbl(merged[["detected_service","is_known_pinning","all_domains","all_%","dnslink_domains","dnslink_%"]])
    _csv(merged, "F_pinning_services", save)

    # Summary rows
    pin_all  = all_df[all_df["is_known_pinning"]==1]["all_domains"].sum()
    pin_dl   = merged[merged["is_known_pinning"]==1]["dnslink_domains"].sum()
    priv_all = all_df[all_df["is_known_pinning"]==0]["all_domains"].sum()
    priv_dl  = merged[merged["is_known_pinning"]==0]["dnslink_domains"].sum()

    print(f"\n  Dedicated IPFS pinning svc — all    : {pin_all:,} ({_pct(pin_all, tot_all)})")
    print(f"  Dedicated IPFS pinning svc — DNSLink: {pin_dl:,}  ({_pct(pin_dl,  tot_dl)})")
    print(f"  Self-hosted / private      — all    : {priv_all:,} ({_pct(priv_all, tot_all)})")
    print(f"  Self-hosted / private      — DNSLink: {priv_dl:,}  ({_pct(priv_dl,  tot_dl)})")


# =============================================================================
# G. Kubo agent versions — DNSLink domains only (non-IPFS sites won't expose these)
# =============================================================================
def section_agents(save: bool):
    _hdr("G. KUBO AGENT VERSIONS  (DNSLink domains — detected from gateway headers)")
    df = _q("""
        SELECT kubo_version,
               COUNT(DISTINCT domain) AS domains,
               SUM(is_outdated)       AS outdated_flag
        FROM agent_versions
        WHERE kubo_version IS NOT NULL
        GROUP BY kubo_version
        ORDER BY version_major DESC, version_minor DESC, version_patch DESC
    """)
    if df.empty:
        print("  No data — run 05_check_liveness.py first.")
        _note("Agent version is only detectable for domains serving via IPFS gateways.")
        return
    tot = df["domains"].sum()
    df["pct"] = df["domains"].map(lambda x: _pct(x, tot))
    _tbl(df)
    _csv(df, "G_agent_versions", save)
    outdated = int(df["outdated_flag"].sum())
    print(f"\n  Outdated Kubo: {outdated:,} / {int(tot):,} ({_pct(outdated, tot)})")
    _note("Non-detectable domains may also be running Kubo behind a CDN that strips headers.")


# =============================================================================
# H. TLS certificates + domain HTTP — ALL domains vs DNSLink subset
# =============================================================================
def section_tls(save: bool):
    _hdr("H. TLS CERTIFICATES & DOMAIN HTTP  (all domains vs DNSLink subset)")

    all_agg = _q("""
        SELECT COUNT(*) AS checked,
               COALESCE(SUM(cert_valid), 0)                                  AS valid,
               COALESCE(SUM(cert_is_expired), 0)                             AS expired,
               COALESCE(SUM(cert_expiring_soon), 0)                          AS expiring,
               COALESCE(SUM(CASE WHEN cert_valid IS NULL THEN 1 ELSE 0 END),0) AS no_https,
               COALESCE(SUM(domain_redirects_to_ipfs), 0)                   AS redirects_to_ipfs
        FROM tls_results
    """).iloc[0]

    dl_agg = _q("""
        SELECT COUNT(DISTINCT t.domain)                                AS checked,
               COALESCE(SUM(t.cert_valid), 0)                         AS valid,
               COALESCE(SUM(t.cert_is_expired), 0)                    AS expired,
               COALESCE(SUM(t.cert_expiring_soon), 0)                 AS expiring,
               COALESCE(SUM(CASE WHEN t.cert_valid IS NULL
                                 THEN 1 ELSE 0 END), 0)               AS no_https,
               COALESCE(SUM(t.domain_redirects_to_ipfs), 0)           AS redirects_to_ipfs
        FROM tls_results t
        JOIN dnslink_records dr ON dr.domain = t.domain
    """).iloc[0]

    if not all_agg["checked"]:
        print("  No data — run 05_check_liveness.py first.")
        return

    ta = int(all_agg["checked"]) or 1
    td = int(dl_agg["checked"])  or 1

    def _i(val) -> int:
        try:
            return int(val) if val is not None else 0
        except (TypeError, ValueError):
            return 0

    rows = [
        ["Domains checked",
            f"{ta:,}",                                    "",
            f"{td:,}",                                    ""],
        ["Valid cert",
            f"{_i(all_agg['valid']):,}",   _pct(all_agg['valid'],    ta),
            f"{_i(dl_agg['valid']):,}",    _pct(dl_agg['valid'],     td)],
        ["Expired cert",
            f"{_i(all_agg['expired']):,}", _pct(all_agg['expired'],  ta),
            f"{_i(dl_agg['expired']):,}",  _pct(dl_agg['expired'],   td)],
        ["Expiring soon",
            f"{_i(all_agg['expiring']):,}",_pct(all_agg['expiring'], ta),
            f"{_i(dl_agg['expiring']):,}", _pct(dl_agg['expiring'],  td)],
        ["No HTTPS",
            f"{_i(all_agg['no_https']):,}",_pct(all_agg['no_https'], ta),
            f"{_i(dl_agg['no_https']):,}", _pct(dl_agg['no_https'],  td)],
        ["Redirects to IPFS gateway",
            f"{_i(all_agg['redirects_to_ipfs']):,}", _pct(all_agg['redirects_to_ipfs'], ta),
            f"{_i(dl_agg['redirects_to_ipfs']):,}",  _pct(dl_agg['redirects_to_ipfs'],  td)],
    ]
    df = pd.DataFrame(rows, columns=["Metric","All count","All %","DNSLink count","DNSLink %"])
    _tbl(df)
    _csv(df, "H_tls_summary", save)

    # Issuer breakdown — all then DNSLink
    for label, join in [("All domains", ""), ("DNSLink domains",
            "JOIN dnslink_records dr ON dr.domain = t.domain")]:
        issuers = _q(f"""
            SELECT COALESCE(NULLIF(t.cert_issuer_org,''),'Unknown') AS issuer,
                   COUNT(*) AS n
            FROM tls_results t {join}
            WHERE t.cert_valid=1
            GROUP BY issuer ORDER BY n DESC LIMIT 8
        """)
        if not issuers.empty:
            print(f"\n  Top cert issuers — {label}:")
            _tbl(issuers)
            _csv(issuers, f"H_issuers_{'all' if 'All' in label else 'dnslink'}", save)

    # HTTP status distribution
    http = _q("""
        SELECT domain_http_status AS status, COUNT(*) AS n
        FROM tls_results WHERE domain_http_status IS NOT NULL
        GROUP BY status ORDER BY n DESC LIMIT 10
    """)
    print("\n  HTTP status distribution (all domains):")
    _tbl(http)
    _csv(http, "H_http_status", save)


# =============================================================================
# I. CID liveness — DNSLink /ipfs/ domains only
# =============================================================================
def section_liveness(save: bool):
    _hdr("I. CID LIVENESS  (DNSLink /ipfs/ domains only)")
    agg = _q("""
        SELECT COUNT(DISTINCT domain) AS domains,
               COUNT(*) AS probes, SUM(is_live) AS live,
               ROUND(AVG(CASE WHEN is_live=1 THEN response_ms END),0) AS avg_ms
        FROM liveness_results
    """).iloc[0]
    if not agg["probes"]:
        print("  No data — run 05_check_liveness.py first.")
        return
    tot = int(agg["probes"])
    rows = [
        ["Domains probed",      int(agg["domains"]), ""],
        ["Total probes",        tot,                  ""],
        ["Live (2xx/3xx)",      int(agg["live"]),     _pct(agg["live"], tot)],
        ["Avg latency (live)",  f"{agg['avg_ms']} ms",""],
    ]
    _tbl(pd.DataFrame(rows, columns=["Metric","Value","%"]))

    gw = _q("""
        SELECT gateway, COUNT(*) AS probes, SUM(is_live) AS live,
               ROUND(AVG(CASE WHEN is_live=1 THEN response_ms END),0) AS avg_ms
        FROM liveness_results GROUP BY gateway ORDER BY live DESC
    """)
    gw["hit_rate"] = gw.apply(lambda r: _pct(r["live"], r["probes"]), axis=1)
    print("\n  Per-gateway hit rate:")
    _tbl(gw)
    _csv(gw, "I_by_gateway", save)

    ct = _q("""
        SELECT CASE
            WHEN content_type LIKE '%html%'         THEN 'text/html'
            WHEN content_type LIKE '%pdf%'          THEN 'application/pdf'
            WHEN content_type LIKE '%json%'         THEN 'application/json'
            WHEN content_type LIKE '%image%'        THEN 'image/*'
            WHEN content_type LIKE '%octet-stream%' THEN 'application/octet-stream'
            WHEN content_type IS NULL OR content_type='' THEN '(none / HEAD)'
            ELSE 'other'
        END AS content_group, COUNT(*) n
        FROM liveness_results WHERE is_live=1
        GROUP BY content_group ORDER BY n DESC
    """)
    print("\n  Content types (live CIDs):")
    _tbl(ct)
    _csv(ct, "I_content_types", save)


# =============================================================================
# J. DAG stats
# =============================================================================
def section_dag(save: bool):
    _hdr("J. DAG SIZE DISTRIBUTION  (DNSLink CIDs via local Kubo)")
    df = _q("""
        SELECT size_bucket,
               COUNT(*) AS cids,
               ROUND(AVG(size_bytes)/1048576.0,2) AS avg_MB,
               ROUND(MIN(size_bytes)/1048576.0,4) AS min_MB,
               ROUND(MAX(size_bytes)/1048576.0,2) AS max_MB,
               ROUND(AVG(num_blocks),1)           AS avg_blocks
        FROM dag_stats WHERE dag_error IS NULL
        GROUP BY size_bucket
        ORDER BY CASE size_bucket
            WHEN 'tiny' THEN 1 WHEN 'small' THEN 2
            WHEN 'medium' THEN 3 WHEN 'large' THEN 4 ELSE 5 END
    """)
    if df.empty:
        print("  No data — run 08_kubo_rpc.py (requires local Kubo daemon).")
        return
    tot = df["cids"].sum()
    df["pct"] = df["cids"].map(lambda x: _pct(x, tot))
    _tbl(df)
    _csv(df, "J_dag_sizes", save)


# =============================================================================
# K. DHT provider counts
# =============================================================================
def section_providers(save: bool):
    _hdr("K. DHT PROVIDER / REPLICATION FACTOR  (DNSLink CIDs)")
    df = _q("""
        SELECT CASE
            WHEN provider_count = 0              THEN '0 (orphaned)'
            WHEN provider_count = 1              THEN '1 (no redundancy)'
            WHEN provider_count BETWEEN 2 AND 5  THEN '2–5'
            WHEN provider_count BETWEEN 6 AND 20 THEN '6–20'
            ELSE '>20'
        END AS bucket,
        COUNT(*) AS cids,
        SUM(has_pinning_svc) AS via_pinning_svc
        FROM provider_records WHERE provider_count IS NOT NULL
        GROUP BY bucket ORDER BY MIN(provider_count)
    """)
    if df.empty:
        print("  No data — run 08_kubo_rpc.py first.")
        return
    tot = df["cids"].sum()
    df["pct"] = df["cids"].map(lambda x: _pct(x, tot))
    _tbl(df)
    _csv(df, "K_provider_counts", save)
    single = _scalar("SELECT COUNT(*) FROM provider_records WHERE provider_count<=1")
    print(f"\n  CIDs with ≤1 provider: {int(single):,} ({_pct(single, tot)})")


# =============================================================================
# L. IPNS key types
# =============================================================================
def section_ipns(save: bool):
    _hdr("L. IPNS KEY TYPES")
    df = _q("""
        SELECT key_type, COUNT(*) AS keys,
               ROUND(AVG(declared_ttl),0) AS avg_ttl_s
        FROM ipns_analysis GROUP BY key_type ORDER BY keys DESC
    """)
    if df.empty:
        print("  No IPNS data — run 09_extended.py --section ipns.")
        return
    tot = df["keys"].sum()
    df["pct"] = df["keys"].map(lambda x: _pct(x, tot))
    _tbl(df)
    _csv(df, "L_ipns_key_types", save)
    rsa = df[df["key_type"]=="rsa_legacy"]["keys"].sum() if "rsa_legacy" in df["key_type"].values else 0
    print(f"\n  Legacy RSA keys: {int(rsa):,} ({_pct(rsa, tot)})")


# =============================================================================
# M. CID deduplication
# =============================================================================
def section_dedup(save: bool):
    _hdr("M. CID DEDUPLICATION")
    total_cids    = _scalar("SELECT COUNT(DISTINCT cid) FROM dnslink_records WHERE link_type='ipfs'")
    total_domains = _scalar("SELECT COUNT(DISTINCT domain) FROM dnslink_records WHERE link_type='ipfs'")
    shared = _q("""
        SELECT cid, COUNT(DISTINCT domain) AS domain_count
        FROM dnslink_records WHERE link_type='ipfs' AND cid IS NOT NULL
        GROUP BY cid HAVING domain_count > 1 ORDER BY domain_count DESC
    """)
    n_shared   = len(shared)
    dom_shared = int(shared["domain_count"].sum()) if not shared.empty else 0
    rows = [
        ["Total unique CIDs",           int(total_cids),   ""],
        ["Total /ipfs/ domains",        int(total_domains), ""],
        ["CIDs shared by >1 domain",    n_shared,           _pct(n_shared,   total_cids)],
        ["Domains serving shared CIDs", dom_shared,         _pct(dom_shared, total_domains)],
    ]
    _tbl(pd.DataFrame(rows, columns=["Metric","Count","%"]))
    if not shared.empty:
        print("\n  Most-duplicated CIDs:")
        _tbl(shared.head(10))
        _csv(shared, "M_shared_cids", save)


# =============================================================================
# N. TLD distribution — ALL domains vs DNSLink subset
# =============================================================================
def section_tld(save: bool, top_n: int = 20):
    _hdr("N. TLD DISTRIBUTION  (all domains vs DNSLink subset)")
    df = _q(f"""
        SELECT d.tld,
               COUNT(DISTINCT d.domain)  AS all_scanned,
               COUNT(DISTINCT dr.domain) AS with_dnslink
        FROM domains d
        LEFT JOIN dnslink_records dr ON dr.domain = d.domain
        WHERE d.tld IS NOT NULL AND d.scanned_dnslink = 1
        GROUP BY d.tld HAVING all_scanned > 50
        ORDER BY with_dnslink DESC, all_scanned DESC
        LIMIT {top_n}
    """)
    if df.empty:
        print("  No TLD data.")
        return
    df["adoption_%"] = df.apply(
        lambda r: _pct(r["with_dnslink"], r["all_scanned"], 2), axis=1)
    _tbl(df)
    _csv(df, "N_tld_distribution", save)


# =============================================================================
# O. ENS cross-reference
# =============================================================================
def section_ens(save: bool):
    _hdr("O. ENS ↔ DNSLINK CID CROSS-REFERENCE  (DNSLink domains)")
    agg = _q("""
        SELECT COUNT(*) AS checked,
               SUM(CASE WHEN ens_cid IS NOT NULL THEN 1 ELSE 0 END) AS has_ens,
               SUM(cids_match) AS match,
               SUM(CASE WHEN ens_cid IS NOT NULL AND cids_match=0 THEN 1 ELSE 0 END) AS drift
        FROM ens_results
    """).iloc[0]
    if not agg["checked"]:
        print("  No data — run 09_extended.py --section ens first.")
        return
    tot = int(agg["checked"])
    ens = int(agg["has_ens"]) or 1
    rows = [
        ["Domains queried",             tot,                ""],
        ["Have .eth ENS record",        int(agg["has_ens"]),_pct(agg["has_ens"], tot)],
        ["ENS CID = DNSLink CID",       int(agg["match"]),  _pct(agg["match"],   ens)],
        ["CID drift (ENS ≠ DNSLink)",   int(agg["drift"]),  _pct(agg["drift"],   ens)],
    ]
    _tbl(pd.DataFrame(rows, columns=["Metric","Count","%"]))
    errs = _q("""
        SELECT ens_error, COUNT(*) n FROM ens_results
        WHERE ens_error IS NOT NULL GROUP BY ens_error ORDER BY n DESC LIMIT 6
    """)
    if not errs.empty:
        print("\n  Resolution failures:")
        _tbl(errs)


# =============================================================================
# P. Longitudinal
# =============================================================================
def section_longitudinal(save: bool):
    _hdr("P. LONGITUDINAL — CID CHURN BY ROUND  (DNSLink domains)")
    df = _q("""
        SELECT round_number, COUNT(*) AS checked,
               SUM(is_live) AS live, SUM(cid_changed) AS changed
        FROM longitudinal GROUP BY round_number ORDER BY round_number
    """)
    if df.empty:
        print("  No data — run 06_longitudinal.py after 24h.")
        return
    df["live_%"]    = df.apply(lambda r: _pct(r["live"],    r["checked"]), axis=1)
    df["changed_%"] = df.apply(lambda r: _pct(r["changed"], r["checked"]), axis=1)
    _tbl(df)
    _csv(df, "P_longitudinal", save)


# ── Dispatch ─────────────────────────────────────────────────────────────────

SECTIONS = {
    "overview":     section_overview,
    "dnslink":      section_dnslink,
    "dnssec":       section_dnssec,
    "geo":          section_geo,
    "asn":          section_asn,
    "pinning":      section_pinning,
    "agents":       section_agents,
    "tls":          section_tls,
    "liveness":     section_liveness,
    "dag":          section_dag,
    "providers":    section_providers,
    "ipns":         section_ipns,
    "dedup":        section_dedup,
    "tld":          section_tld,
    "ens":          section_ens,
    "longitudinal": section_longitudinal,
}


def main():
    parser = argparse.ArgumentParser(description="IPFS Field Study — Analysis")
    parser.add_argument("--csv",     action="store_true",
                        help=f"Write CSVs to {ANALYSIS_OUTPUT_DIR}/")
    parser.add_argument("--section", choices=list(SECTIONS.keys()),
                        help="Run only one section")
    args = parser.parse_args()

    if not os.path.exists(DB_PATH):
        sys.exit(f"Database not found: {DB_PATH}")

    print(f"\n  IPFS Field Study — Analysis Report")
    print(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Database  : {DB_PATH}")

    if args.section:
        SECTIONS[args.section](args.csv)
    else:
        for fn in SECTIONS.values():
            fn(args.csv)

    if args.csv:
        print(f"\n  CSVs written to ./{ANALYSIS_OUTPUT_DIR}/")


if __name__ == "__main__":
    main()