# =============================================================================
# db.py  —  SQLite schema, migration, and shared helpers  (v2)
# =============================================================================

import contextlib
import sqlite3
from config import DB_PATH

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA = """
-- ── Core domain list ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domains (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    domain           TEXT    UNIQUE NOT NULL,
    rank             INTEGER,
    tld              TEXT,           -- extracted TLD for distribution analysis
    -- scan progress flags  (0=pending  1=done  -1=error)
    scanned_dnslink  INTEGER DEFAULT 0,
    scanned_dnssec   INTEGER DEFAULT 0,
    scanned_geo      INTEGER DEFAULT 0,
    scanned_live     INTEGER DEFAULT 0,
    scanned_tls      INTEGER DEFAULT 0,
    scanned_dag      INTEGER DEFAULT 0,
    scanned_providers INTEGER DEFAULT 0,
    scanned_ipns     INTEGER DEFAULT 0,
    scanned_ens      INTEGER DEFAULT 0
);

-- ── DNSLink TXT records ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dnslink_records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT NOT NULL,
    link_type  TEXT,      -- 'ipfs' | 'ipns' | 'unknown'
    cid        TEXT,      -- extracted CID or IPNS key
    raw_value  TEXT,      -- /ipfs/<cid> or /ipns/<key>
    raw_txt    TEXT,      -- full TXT record string
    ttl        INTEGER,
    queried_at TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── DNSSEC validation (all DNSLink domains, including no-DNSSEC ones) ───────
CREATE TABLE IF NOT EXISTS dnssec_results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    domain           TEXT NOT NULL,
    -- individual checks
    has_dnskey       INTEGER DEFAULT 0,   -- DNSKEY RR at apex
    has_ds           INTEGER DEFAULT 0,   -- DS RR at parent
    has_rrsig_txt    INTEGER DEFAULT 0,   -- RRSIG over _dnslink TXT rrset
    chain_valid      INTEGER DEFAULT 0,   -- full chain trusted (all 4 pass)
    ad_flag          INTEGER DEFAULT 0,   -- AD bit set by validating resolver
    -- 4-bucket classification:
    --   'full'           : chain_valid=1
    --   'partial_no_ds'  : has_dnskey=1, has_ds=0  (most common operator mistake)
    --   'partial_no_rrsig': has_ds=1, has_rrsig_txt=0
    --   'broken'         : has_rrsig_txt=1, chain_valid=0  (expired/wrong key)
    --   'none'           : no DNSSEC infrastructure at all
    dnssec_class     TEXT DEFAULT 'none',
    validation_error TEXT,
    queried_at       TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── IP geolocation + ASN ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS geo_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    ip_address   TEXT,
    rdns_hostname TEXT,              -- reverse-DNS PTR record
    country      TEXT,
    country_code TEXT,
    region       TEXT,
    city         TEXT,
    isp          TEXT,
    org          TEXT,
    asn          TEXT,               -- e.g. "AS13335"
    asn_name     TEXT,               -- e.g. "Cloudflare, Inc."
    queried_at   TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── Pinning service classification ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pinning_detection (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    domain           TEXT NOT NULL,
    ip_address       TEXT,
    -- result
    detected_service TEXT,   -- 'Cloudflare' | 'Pinata' | ... | 'private_cloud' | 'private_residential'
    detection_method TEXT,   -- pipe-separated list: 'asn|header|rdns'
    confidence       TEXT,   -- 'high' | 'medium' | 'low'
    is_known_pinning INTEGER DEFAULT 0,   -- 1 = dedicated IPFS pinning service
    is_private_node  INTEGER DEFAULT 0,   -- 1 = not a known commercial provider
    checked_at       TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── TLS certificate + domain HTTP check ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS tls_results (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    domain                  TEXT NOT NULL,
    -- TLS certificate
    cert_valid              INTEGER,   -- 1=valid, 0=invalid, NULL=no HTTPS
    cert_issuer_org         TEXT,      -- e.g. "Let's Encrypt"
    cert_subject_cn         TEXT,
    cert_expiry_iso         TEXT,
    cert_days_remaining     INTEGER,
    cert_is_expired         INTEGER DEFAULT 0,
    cert_expiring_soon      INTEGER DEFAULT 0,   -- within CERT_WARN_DAYS
    cert_error              TEXT,
    -- Plain domain HTTP probe (follows redirects)
    domain_http_status      INTEGER,
    domain_redirects_to_ipfs INTEGER DEFAULT 0,  -- final URL contains /ipfs/ or dnslink
    domain_final_url        TEXT,
    checked_at              TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── Kubo agent version (detected from HTTP response headers) ────────────────
CREATE TABLE IF NOT EXISTS agent_versions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    domain         TEXT NOT NULL,
    gateway        TEXT,            -- which gateway / source returned the header
    raw_agent      TEXT,            -- full raw string, e.g. "kubo/0.28.0/..."
    kubo_version   TEXT,            -- parsed semver string, e.g. "0.28.0"
    version_major  INTEGER,
    version_minor  INTEGER,
    version_patch  INTEGER,
    is_outdated    INTEGER DEFAULT 0,
    detection_src  TEXT,            -- header name: 'Server' | 'X-Ipfs-Version' | 'Via'
    checked_at     TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── Gateway liveness checks ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS liveness_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT NOT NULL,
    cid             TEXT,
    gateway         TEXT,
    http_status     INTEGER,
    content_type    TEXT,
    content_length  INTEGER,
    response_ms     REAL,
    is_live         INTEGER DEFAULT 0,
    error           TEXT,
    checked_at      TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── DAG statistics (requires local Kubo node) ───────────────────────────────
CREATE TABLE IF NOT EXISTS dag_stats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL,
    cid         TEXT NOT NULL,
    size_bytes  INTEGER,     -- total DAG payload size in bytes
    num_blocks  INTEGER,     -- number of unique blocks
    -- size category (computed on insert)
    size_bucket TEXT,        -- 'tiny'(<1KB) 'small'(<1MB) 'medium'(<1GB) 'large'(>=1GB)
    dag_error   TEXT,
    queried_at  TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── DHT provider records (requires local Kubo node) ─────────────────────────
CREATE TABLE IF NOT EXISTS provider_records (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    domain           TEXT NOT NULL,
    cid              TEXT NOT NULL,
    provider_count   INTEGER,        -- total unique provider peers
    peer_ids_json    TEXT,           -- JSON array of peer ID strings
    has_pinning_svc  INTEGER DEFAULT 0,  -- 1 if a known pinning-service peer is among providers
    pinning_svc_name TEXT,           -- which one, if detected
    queried_at       TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── IPNS key analysis ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipns_analysis (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    ipns_key     TEXT,
    key_type     TEXT,    -- 'ed25519' | 'rsa_legacy' | 'unknown'
    declared_ttl INTEGER, -- TTL from the DNS record (seconds)
    -- from Kubo RPC (optional, requires local node)
    sequence_num  INTEGER,
    validity_iso  TEXT,
    validity_ok   INTEGER DEFAULT 0,
    rpc_error     TEXT,
    queried_at    TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── ENS cross-reference ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ens_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT NOT NULL,
    ens_name        TEXT,      -- e.g. "example.eth"
    ens_cid         TEXT,      -- CID decoded from ENS contenthash
    dnslink_cid     TEXT,      -- CID from our DNSLink scan (for comparison)
    cids_match      INTEGER DEFAULT 0,
    ens_error       TEXT,
    queried_at      TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── Longitudinal re-scans ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS longitudinal (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    round_number INTEGER,
    cid_at_check TEXT,
    cid_changed  INTEGER DEFAULT 0,
    is_live      INTEGER DEFAULT 0,
    checked_at   TEXT,
    FOREIGN KEY (domain) REFERENCES domains(domain)
);

-- ── Indexes ─────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_domains_dnslink   ON domains(scanned_dnslink);
CREATE INDEX IF NOT EXISTS idx_domains_dnssec    ON domains(scanned_dnssec);
CREATE INDEX IF NOT EXISTS idx_domains_geo       ON domains(scanned_geo);
CREATE INDEX IF NOT EXISTS idx_domains_live      ON domains(scanned_live);
CREATE INDEX IF NOT EXISTS idx_domains_tls       ON domains(scanned_tls);
CREATE INDEX IF NOT EXISTS idx_domains_dag       ON domains(scanned_dag);
CREATE INDEX IF NOT EXISTS idx_domains_tld       ON domains(tld);
CREATE INDEX IF NOT EXISTS idx_dnslink_domain    ON dnslink_records(domain);
CREATE INDEX IF NOT EXISTS idx_dnslink_cid       ON dnslink_records(cid);
CREATE INDEX IF NOT EXISTS idx_dnslink_type      ON dnslink_records(link_type);
CREATE INDEX IF NOT EXISTS idx_dnssec_domain     ON dnssec_results(domain);
CREATE INDEX IF NOT EXISTS idx_dnssec_class      ON dnssec_results(dnssec_class);
CREATE INDEX IF NOT EXISTS idx_geo_domain        ON geo_results(domain);
CREATE INDEX IF NOT EXISTS idx_geo_country       ON geo_results(country_code);
CREATE INDEX IF NOT EXISTS idx_geo_asn           ON geo_results(asn);
CREATE INDEX IF NOT EXISTS idx_pinning_domain    ON pinning_detection(domain);
CREATE INDEX IF NOT EXISTS idx_pinning_service   ON pinning_detection(detected_service);
CREATE INDEX IF NOT EXISTS idx_tls_domain        ON tls_results(domain);
CREATE INDEX IF NOT EXISTS idx_agent_domain      ON agent_versions(domain);
CREATE INDEX IF NOT EXISTS idx_live_domain       ON liveness_results(domain);
CREATE INDEX IF NOT EXISTS idx_dag_domain        ON dag_stats(domain);
CREATE INDEX IF NOT EXISTS idx_dag_cid           ON dag_stats(cid);
CREATE INDEX IF NOT EXISTS idx_prov_domain       ON provider_records(domain);
CREATE INDEX IF NOT EXISTS idx_prov_cid          ON provider_records(cid);
CREATE INDEX IF NOT EXISTS idx_ipns_domain       ON ipns_analysis(domain);
CREATE INDEX IF NOT EXISTS idx_ens_domain        ON ens_results(domain);
CREATE INDEX IF NOT EXISTS idx_long_domain       ON longitudinal(domain);
CREATE INDEX IF NOT EXISTS idx_long_round        ON longitudinal(round_number);
"""

# Columns added in v2 that may be absent in existing DBs (migration).
_V2_MIGRATIONS = [
    ("domains",        "tld",                  "TEXT"),
    ("domains",        "scanned_tls",           "INTEGER DEFAULT 0"),
    ("domains",        "scanned_dag",           "INTEGER DEFAULT 0"),
    ("domains",        "scanned_providers",     "INTEGER DEFAULT 0"),
    ("domains",        "scanned_ipns",          "INTEGER DEFAULT 0"),
    ("domains",        "scanned_ens",           "INTEGER DEFAULT 0"),
    ("dnssec_results", "dnssec_class",          "TEXT DEFAULT 'none'"),
    ("geo_results",    "rdns_hostname",         "TEXT"),
]


# ---------------------------------------------------------------------------
# Connection context manager
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def get_db(path: str = DB_PATH):
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema init + migration
# ---------------------------------------------------------------------------
def _migrate(conn: sqlite3.Connection):
    """Add columns introduced in v2 if they are missing (idempotent)."""
    existing: dict[str, set] = {}
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
    for table in tables:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        existing[table] = cols

    for table, column, col_type in _V2_MIGRATIONS:
        if table in existing and column not in existing[table]:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
            print(f"[db] Migration: added {table}.{column}")


def init_db(path: str = DB_PATH):
    with get_db(path) as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
        # Backfill TLD column for any rows imported before v2
        conn.execute("""
            UPDATE domains SET tld = LOWER(SUBSTR(domain, INSTR(domain, '.') + 1))
            WHERE tld IS NULL AND INSTR(domain, '.') > 0
        """)
    print(f"[db] Database ready → {path}")


# ---------------------------------------------------------------------------
# Shared helpers used by multiple scripts
# ---------------------------------------------------------------------------
def mark_domain(conn: sqlite3.Connection, domain: str, column: str, value: int = 1):
    conn.execute(f"UPDATE domains SET {column}=? WHERE domain=?", (value, domain))


def classify_dnssec(has_dnskey: int, has_ds: int,
                    has_rrsig_txt: int, chain_valid: int) -> str:
    """
    Return one of five DNSSEC classification buckets:
      full            – all four checks pass
      partial_no_ds   – zone has DNSKEY but no DS at parent (common operator mistake)
      partial_no_rrsig– DS registered but _dnslink TXT is not signed
      broken          – RRSIG present but validation fails (expired / wrong key)
      none            – no DNSSEC infrastructure at all
    """
    if chain_valid:
        return "full"
    if has_rrsig_txt and not chain_valid:
        return "broken"
    if has_dnskey and not has_ds:
        return "partial_no_ds"
    if has_ds and not has_rrsig_txt:
        return "partial_no_rrsig"
    return "none"


if __name__ == "__main__":
    init_db()
