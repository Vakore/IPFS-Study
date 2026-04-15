# IPFS Field Study — Setup & Running Guide (v2)

A measurement study of DNSLink usage, DNSSEC adoption, geographic and
infrastructural centralisation, content liveness, DAG complexity, DHT
provider distribution, and naming-system consistency across the IPFS ecosystem.

---

## Table of Contents

1. [Research Questions](#1-research-questions)
2. [Architecture Overview](#2-architecture-overview)
3. [Prerequisites](#3-prerequisites)
4. [Installation](#4-installation)
5. [Configuration](#5-configuration)
6. [Running the Pipeline](#6-running-the-pipeline)
7. [Longitudinal Scheduling](#7-longitudinal-scheduling)
8. [Analyzing Results](#8-analyzing-results)
9. [Rate Limiting & Ethics](#9-rate-limiting--ethics)
10. [Troubleshooting](#10-troubleshooting)
11. [Data Dictionary](#11-data-dictionary)

---

## 1. Research Questions

| # | Question | Script(s) | Analysis section |
|---|---|---|---|
| RQ1  | How widespread is DNSLink across top domains? | `02` | A, B |
| RQ2  | What fraction of DNSLink records are DNSSEC-protected? | `03` | C |
| RQ2a | Which DNSSEC failure mode is most common (5 buckets)? | `03` | C |
| RQ3  | How centralised is IPFS geographically? | `04` | D |
| RQ4  | How centralised is IPFS by hosting provider (ASN)? | `04` | E |
| RQ5  | What fraction of CIDs are served by dedicated pinning services vs. private nodes? | `04`, `05` | F |
| RQ6  | Are IPFS nodes running outdated / vulnerable Kubo versions? | `05` | G |
| RQ7  | What fraction of advertised CIDs are actually reachable? | `05` | I |
| RQ8  | Are domain TLS certificates valid? Who issues them? | `05` | H |
| RQ9  | What content types and sizes are published via IPFS? | `05`, `08` | I, J |
| RQ10 | How many peers replicate each CID (replication factor)? | `08` | K |
| RQ11 | Are IPNS records using modern (Ed25519) or legacy (RSA) keys? | `09` | L |
| RQ12 | Is any content duplicated across multiple DNSLink domains? | `09` | M |
| RQ13 | Which TLDs adopt DNSLink most? | `09` | N |
| RQ14 | Do ENS (.eth) and DNSLink records stay in sync? | `09` | O |
| RQ15 | How dynamic is IPFS content? (CID churn over time) | `06` | P |

---

## 2. Architecture Overview

```
Tranco top-1M list
       │
       ▼
01_fetch_domains.py ───────────────► domains table
       │
       ▼
02_scan_dnslink.py ─────────────────► dnslink_records table
       │
       ├──► 03_validate_dnssec.py ──► dnssec_results table
       │        (all DNSLink domains, 5-bucket classification)
       │
       ├──► 04_geo_asn.py ──────────► geo_results table
       │        (IP → country, ASN, rDNS)   pinning_detection table
       │
       ├──► 05_check_liveness.py ───► liveness_results table
       │        (CID gateway probes)         agent_versions table
       │        (Kubo version headers)       tls_results table
       │        (TLS cert + domain HTTP)
       │
       ├──► 06_longitudinal.py ─────► longitudinal table  (run daily via cron)
       │
       ├──► 08_kubo_rpc.py ─────────► dag_stats table
       │        (requires local Kubo)        provider_records table
       │
       └──► 09_extended.py ─────────► ipns_analysis table
                                       ens_results table
                                       (also: dedup + TLD — pure SQL)
                                               │
                                               ▼
                                       07_analyze.py ──► 16 sections, CSV export
```

All data lives in a single SQLite file (`ipfs_study.db`).
Every script is **interruption-safe**: Ctrl-C at any point, re-run, and it
resumes from exactly where it left off.

---

## 3. Prerequisites

| Tool | Version | Required | Purpose |
|---|---|---|---|
| Python | ≥ 3.11 | Yes | All scripts |
| Go | ≥ 1.21 | Optional | zdns fast-path DNS scanner |
| Kubo (go-ipfs) | ≥ 0.26 | Optional | Scripts `08` (DAG stats + provider counts) |

---

## 4. Installation

### 4a. Set up the project directory

```bash
cd ipfs-field-study
```

### 4b. Create a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows PowerShell
```

### 4c. Install Python dependencies

```bash
pip install -r requirements.txt
```

Packages installed:

| Package | Purpose |
|---|---|
| `dnspython` | DNS + DNSSEC queries |
| `requests` | HTTP gateway probes, geo API, Ethereum RPC |
| `tqdm` | Progress bars |
| `ipwhois` | ASN fallback lookups |
| `pandas` | Analysis and CSV export |
| `tabulate` | Pretty-print tables |
| `urllib3` | HTTP internals |
| `pycryptodome` | Keccak-256 for ENS namehash (ENS section of `09`) |

### 4d. (Optional) Install zdns for faster DNS scanning

zdns is a Go-based mass DNS resolver that can scan millions of domains in
minutes. Without it the Python/dnspython backend (~40 q/s) works fine for
up to ~100k domains.

```bash
# Requires Go 1.21+
go install github.com/zmap/zdns@latest

# go install puts binaries in ~/go/bin — add it to PATH if needed:
export PATH=$PATH:$(go env GOPATH)/bin

# Make permanent:
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# Verify:
zdns --version
```

Then in `config.py` set `USE_ZDNS = True`.

### 4e. (Optional) Install and initialise Kubo

Required only for script `08` (DAG statistics and DHT provider counts).

```bash
# Debian/Ubuntu
wget https://github.com/ipfs/kubo/releases/latest/download/kubo_*_linux-amd64.tar.gz
tar -xvzf kubo_*.tar.gz && cd kubo && sudo bash install.sh

# macOS (Homebrew)
brew install ipfs

# First-time initialisation:
ipfs init

# Start the daemon (leave running in a separate terminal):
ipfs daemon
```

Confirm it is running before executing `08_kubo_rpc.py`:

```bash
curl -s http://localhost:5001/api/v0/version
# {"Version":"0.28.0", ...}
```

---

## 5. Configuration

All tuneable values live in **`config.py`**. Key settings to review before
your first run:

```python
# ── Domain list ──────────────────────────────────────────────────────
DOMAIN_SAMPLE_SIZE = 50_000   # start with 5_000 for a test run

# ── Rate limits ──────────────────────────────────────────────────────
DNS_QPS  = 40     # DNS queries per second
IPFS_RPS = 5      # requests/sec to IPFS gateways
GEO_RPS  = 10     # requests/sec to ip-api.com

# ── Kubo version threshold ────────────────────────────────────────────
# Nodes running an older version are flagged as outdated.
# Update this to the current stable release before each study run.
KUBO_MINIMUM_VERSION = (0, 26, 0)

# ── Longitudinal ──────────────────────────────────────────────────────
LONGITUDINAL_ROUNDS         = 7
LONGITUDINAL_INTERVAL_HOURS = 24

# ── ENS ───────────────────────────────────────────────────────────────
ENABLE_ENS = True   # set False to skip Ethereum RPC calls
```

**Rate limit tip:** Run with `DOMAIN_SAMPLE_SIZE = 5000` and `DNS_QPS = 20`
first. Once the full pipeline completes cleanly on 5k domains, scale up.

---

## 6. Running the Pipeline

Run scripts **in order**. Steps 3–5 and 8–9 can be run in parallel once
Step 2 has finished, since they all read from `dnslink_records` and never
write to each other's tables.

---

### Step 1 — Import the domain list

```bash
python 01_fetch_domains.py
```

Downloads the Tranco top-1M CSV (~6 MB zip), extracts TLDs, and imports
domains into the `domains` table. Safe to re-run — existing rows are skipped.

```bash
# Options
python 01_fetch_domains.py --sample 10000        # import only 10k domains
python 01_fetch_domains.py --custom my_list.txt  # use a plain-text domain list
python 01_fetch_domains.py --redownload          # force fresh download
```

Expected output:
```
[01] Downloading domain list from https://tranco-list.eu/top-1m.csv.zip
Downloading: 100%|████| 6.3M/6.3M [00:03]
[01] Done — 50,000 domains imported (new rows only).
```

---

### Step 2 — Scan for DNSLink records

```bash
python 02_scan_dnslink.py
```

Queries `_dnslink.<domain>` TXT records for every domain. This is the longest
step: ~20–40 minutes for 50k domains at 40 q/s. DNSLink is rare in the wild
— expect roughly 0.1–0.5% hit rate.

```bash
# Options
python 02_scan_dnslink.py --workers 30 --qps 60   # faster (watch for blocks)
python 02_scan_dnslink.py --limit 5000            # only process N pending domains
```

If `USE_ZDNS = True` in config, this runs zdns instead of the Python backend
and completes in minutes rather than hours.

Expected output:
```
[02] Backend: dnspython  workers=20  qps=40
Scanning DNSLink: 100%|████| 50000/50000 [22:18, found=47]
[02] Done — 47 DNSLink records found across 50,000 domains.
```

---

### Step 3 — DNSSEC validation (all DNSLink domains)

```bash
python 03_validate_dnssec.py
```

Runs four DNSSEC checks on **every** domain that has a DNSLink record,
including domains with zero DNSSEC infrastructure. Every domain gets a row
in `dnssec_results` and a classification into one of five buckets:

| Bucket | Meaning |
|---|---|
| `full` | DNSKEY + DS + RRSIG + AD flag — complete chain |
| `partial_no_ds` | Zone is signed but DS not registered at registrar |
| `partial_no_rrsig` | DS registered but `_dnslink` TXT is unsigned |
| `broken` | RRSIG present but chain validation fails (expired / wrong key) |
| `none` | No DNSSEC infrastructure at all |

The `none` bucket will dominate. That is the expected finding and is exactly
what makes the bucket distribution interesting.

```bash
python 03_validate_dnssec.py --workers 10 --qps 20
```

Expected output:
```
[03] DNSLink domains to validate: 47
DNSSEC validation: 100%|████| 47/47 [00:28]
[03] Done — 47 domains validated.
     Bucket breakdown:
       none                   38  (80.9%)
       partial_no_ds           5  (10.6%)
       full                    3   (6.4%)
       broken                  1   (2.1%)
```

---

### Step 4 — Geo / ASN / rDNS / pinning detection

```bash
python 04_geo_asn.py
```

For each DNSLink domain:
1. Resolves the A record
2. Performs a reverse-DNS (PTR) lookup
3. Batch-queries ip-api.com (100 IPs per POST) for country, region, ISP, ASN
4. Runs a 3-signal pinning-service classifier (ASN name + rDNS + HTTP headers)
   and writes to `pinning_detection`

Classification output distinguishes:
- **Dedicated IPFS pinning service** (Cloudflare, Pinata, Infura, Fleek, etc.)
- **Cloud-hosted private node** (AWS, Hetzner, DigitalOcean, etc.)
- **Residential / unknown private node**

```bash
python 04_geo_asn.py --batch 100   # IPs per geo-API request (max 100)
```

Expected output:
```
[04] Domains to process: 47
Geo + rDNS + pinning: 100%|████| 47/47 [00:14]
[04] Done — 47 domains geo-located and classified.
```

---

### Step 5 — CID liveness, Kubo versions, TLS, and domain HTTP

```bash
python 05_check_liveness.py
```

Runs two phases:

**Phase 1 — CID gateway probes**
HEAD-requests each `/ipfs/` CID via every configured gateway. Records HTTP
status, content-type, latency, and:
- **Kubo agent version** from `Server`, `X-Ipfs-Version`, and `Via` headers.
  Versions older than `KUBO_MINIMUM_VERSION` are flagged outdated.
- **Pinning-service header signals** (e.g. `CF-Ray`, `X-Pinata-*`) which
  upgrade the confidence level in `pinning_detection`.

**Phase 2 — TLS certificate + domain HTTP**
Opens a real SSL socket to port 443, reads the peer certificate, and records:
issuer, expiry date, days remaining, expired/expiring-soon flags. Then does a
plain HTTP GET following redirects to record the final status code and whether
the domain already redirects to an IPFS gateway.

```bash
# Options
python 05_check_liveness.py --workers 20
python 05_check_liveness.py --skip-tls            # skip Phase 2
python 05_check_liveness.py --gateways https://cloudflare-ipfs.com/ipfs/ https://ipfs.io/ipfs/
```

Expected output:
```
[05] CIDs to probe: 35 × 4 gateways = 140 requests
CID liveness: 100%|████| 140/140 [01:52, live=89]
[05] CID liveness done — 89/140 live probes.
TLS + HTTP: 100%|████| 47/47 [00:38, expired=3]
[05] TLS done — 3 expired certs found.
```

---

### Step 6 — Longitudinal re-scanning (run daily)

```bash
# First run (bypasses the interval check):
python 06_longitudinal.py --force

# Subsequent runs (respects LONGITUDINAL_INTERVAL_HOURS — skip if too soon):
python 06_longitudinal.py
```

Re-queries every baseline DNSLink domain and compares the current CID to the
round-0 value. Records whether the CID changed and whether the record is still
live. State is persisted in `longitudinal_state.json` so cron runs are fully
automatic.

See [Section 7](#7-longitudinal-scheduling) for cron/systemd setup.

---

### Step 7 (optional) — DAG stats and DHT provider counts

> **Requires a running Kubo daemon.**  Start with `ipfs daemon` before running
> this script.

```bash
python 08_kubo_rpc.py
```

For every `/ipfs/` CID:
- Calls `/api/v0/dag/stat` to get total size in bytes and block count
- Calls `/api/v0/routing/findprovs` to count DHT-announcing peers

Size buckets: `tiny` (<1 KB), `small` (<1 MB), `medium` (<1 GB), `large` (≥1 GB).

Provider multiaddresses are also scanned for known pinning-service hostnames,
giving an independent confirmation of the centralisation finding.

```bash
# Options (keep workers low — Kubo is a single local node)
python 08_kubo_rpc.py --workers 4 --rps 2
```

Expected output:
```
[08] Kubo daemon found — version 0.28.0
[08] CIDs to query: 35
DAG + Providers: 100%|████| 35/35 [02:14, errors=1]
[08] Done — 35 CIDs queried.
     Size distribution:
       tiny        18  (51.4%)
       small       12  (34.3%)
       medium       4  (11.4%)
       large        1   (2.9%)
```

---

### Step 8 (optional) — Extended analysis

```bash
python 09_extended.py           # all four sections
python 09_extended.py --section ipns    # IPNS key types only
python 09_extended.py --section dedup  # CID deduplication only
python 09_extended.py --section tld    # TLD distribution only
python 09_extended.py --section ens    # ENS cross-reference only
```

Four independent sections — each can be run standalone:

**IPNS key type classification**
Classifies every `/ipns/` key by its multibase prefix — no network call
needed. `k51…` and `12D3…` prefixes indicate modern Ed25519 keys; `Qm…`
indicates legacy RSA (weaker). Results go to `ipns_analysis`.

**CID deduplication**
Pure SQL — identifies CIDs shared by more than one DNSLink domain. Identical
CIDs mean identical content (mirrors, forks, or stale copies). No network
required.

**TLD distribution**
Pure SQL — counts DNSLink adoption rate per TLD (`.com`, `.io`, `.xyz`, etc.)
to reveal whether this is a developer-niche tool or crossing into general web.
No network required.

**ENS cross-reference**
For each DNSLink domain, queries ENS (`<basename>.eth`) via raw Ethereum
JSON-RPC (no library required). Decodes the contenthash bytes to an IPFS CID
and compares it to the DNSLink CID. Drift (ENS ≠ DNSLink) indicates
inconsistent content across naming systems.

---

## 7. Longitudinal Scheduling

### cron (Linux / macOS)

```bash
crontab -e
```

Add (runs daily at 6 AM):
```
0 6 * * *  cd /path/to/ipfs-field-study && \
           /path/to/.venv/bin/python 06_longitudinal.py \
           >> logs/longitudinal.log 2>&1
```

### systemd timer (Linux)

`/etc/systemd/system/ipfs-study.service`:
```ini
[Unit]
Description=IPFS Field Study Longitudinal Scan

[Service]
WorkingDirectory=/path/to/ipfs-field-study
ExecStart=/path/to/.venv/bin/python 06_longitudinal.py
User=youruser
```

`/etc/systemd/system/ipfs-study.timer`:
```ini
[Unit]
Description=IPFS study — run daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now ipfs-study.timer
```

### Checking progress

```bash
cat longitudinal_state.json
# {"next_round": 3, "last_run_iso": "2025-04-10T06:00:12+00:00", "completed_rounds": [1, 2]}
```

---

## 8. Analyzing Results

```bash
# All 16 sections to stdout
python 07_analyze.py

# Single section
python 07_analyze.py --section dnssec
python 07_analyze.py --section pinning
python 07_analyze.py --section dag

# Export all sections as CSVs to analysis_output/
python 07_analyze.py --csv
```

### Available sections

| Flag | Content | Maps to RQ |
|---|---|---|
| `overview` | Scan completion rates, hit counts | — |
| `dnslink` | /ipfs/ vs /ipns/, TTL distribution | RQ1 |
| `dnssec` | 5-bucket breakdown, individual check rates, error types | RQ2, RQ2a |
| `geo` | DNSLink domains by country, top-3 concentration | RQ3 |
| `asn` | Top ASNs by domain count, concentration | RQ4 |
| `pinning` | Pinning service vs cloud vs private node | RQ5 |
| `agents` | Kubo version distribution, outdated fraction | RQ6 |
| `tls` | Cert validity, issuers, domain HTTP status | RQ8 |
| `liveness` | Live CID rate, per-gateway, content types | RQ7, RQ9 |
| `dag` | Size bucket distribution, avg block count | RQ9 |
| `providers` | Replication factor histogram, pinning-svc via DHT | RQ10 |
| `ipns` | Ed25519 vs RSA key types, TTL stats | RQ11 |
| `dedup` | Shared CIDs, domain count per CID | RQ12 |
| `tld` | TLD adoption rates | RQ13 |
| `ens` | ENS presence, CID match/drift | RQ14 |
| `longitudinal` | CID churn per round, persistence rate | RQ15 |

---

## 9. Rate Limiting & Ethics

- **DNS**: Default 40 q/s spread across three resolvers is polite. Do not
  exceed ~100 q/s from a single IP without controlling the resolver.
- **IPFS gateways**: Requests are HEAD-only — no content is downloaded.
  Keep `IPFS_RPS` at 5 or below per gateway.
- **ip-api.com**: Free tier allows ~45 req/s. Batch endpoint (100 IPs/POST)
  means 100 domains consume only 1 request. Default settings stay well
  within limits.
- **Ethereum RPC**: Cloudflare's free `cloudflare-eth.com` endpoint is used.
  The ENS section adds a 250ms delay between domains (~4 domains/s).
- **Kubo RPC**: Runs against your own local daemon — no external rate limit,
  but keep `--workers` low (4–6) to avoid overwhelming a single node.
- **Transparency**: The User-Agent string in `05_check_liveness.py` reads
  `IPFS-FieldStudy/2.0 (academic; cs780)`. Update it to include your
  institution email if submitting for publication.
- **HTTP 429**: If any service returns Too Many Requests, lower the
  relevant `_RPS` constant in `config.py` and re-run.

---

## 10. Troubleshooting

### `No module named dns`
```bash
pip install dnspython
```

### `No module named Crypto` (ENS section fails)
```bash
pip install pycryptodome
```

### zdns not found after `go install`
```bash
export PATH=$PATH:$(go env GOPATH)/bin
# then make permanent — add to ~/.bashrc or ~/.zshrc
```

### Script hangs or is very slow
Lower `--workers` and `--qps`. High concurrency causes resolvers to
rate-limit you, which is slower than a modest steady rate.

### Kubo daemon not reachable
Make sure `ipfs daemon` is running in another terminal before running `08`.
Test with: `curl http://localhost:5001/api/v0/version`

### ip-api returns all `"fail"` statuses
Free-tier rate limit hit. Wait 60 seconds, then lower `GEO_RPS` in config.

### Database locked
Only one script should write at a time. Find orphaned processes:
```bash
fuser ipfs_study.db      # Linux
lsof ipfs_study.db       # macOS
```

### Upgrading from v1 (existing database)
The `db.py` migration helper adds all new columns automatically on startup.
Just run any v2 script and the existing database will be upgraded in-place:
```bash
python db.py             # explicit migration
```

### Starting completely fresh
```bash
rm ipfs_study.db longitudinal_state.json
python 01_fetch_domains.py
```

---

## 11. Data Dictionary

### `domains`
| Column | Type | Description |
|---|---|---|
| domain | TEXT | Fully-qualified domain name |
| rank | INT | Tranco rank |
| tld | TEXT | Extracted TLD (e.g. `com`, `io`) |
| scanned_dnslink | INT | 0=pending, 1=done |
| scanned_dnssec | INT | 0=pending, 1=done |
| scanned_geo | INT | 0=pending, 1=done |
| scanned_live | INT | 0=pending, 1=done |
| scanned_tls | INT | 0=pending, 1=done |
| scanned_dag | INT | 0=pending, 1=done |
| scanned_providers | INT | 0=pending, 1=done |
| scanned_ipns | INT | 0=pending, 1=done |
| scanned_ens | INT | 0=pending, 1=done |

### `dnslink_records`
| Column | Type | Description |
|---|---|---|
| domain | TEXT | Domain with the DNSLink TXT record |
| link_type | TEXT | `ipfs` or `ipns` |
| cid | TEXT | Extracted CID or IPNS key |
| raw_value | TEXT | Full `/ipfs/…` or `/ipns/…` value |
| raw_txt | TEXT | Complete TXT record string |
| ttl | INT | DNS TTL in seconds |

### `dnssec_results`
| Column | Type | Description |
|---|---|---|
| has_dnskey | INT | DNSKEY RR at zone apex (0/1) |
| has_ds | INT | DS record at parent zone (0/1) |
| has_rrsig_txt | INT | RRSIG covering the `_dnslink` TXT rrset (0/1) |
| chain_valid | INT | All four checks passed (0/1) |
| ad_flag | INT | Validating resolver set the AD bit (0/1) |
| dnssec_class | TEXT | `full` / `partial_no_ds` / `partial_no_rrsig` / `broken` / `none` |
| validation_error | TEXT | Human-readable failure reason if any |

### `geo_results`
| Column | Type | Description |
|---|---|---|
| ip_address | TEXT | Resolved A record |
| rdns_hostname | TEXT | Reverse-DNS PTR hostname |
| country / country_code | TEXT | Full name and ISO 3166-1 alpha-2 code |
| region / city | TEXT | Sub-national region and city |
| isp / org | TEXT | ISP and organisation strings from ip-api |
| asn | TEXT | Autonomous System Number (e.g. `AS13335`) |
| asn_name | TEXT | ASN organisation name (e.g. `Cloudflare, Inc.`) |

### `pinning_detection`
| Column | Type | Description |
|---|---|---|
| detected_service | TEXT | Service name or `private_residential` / `private_hosted` |
| detection_method | TEXT | Pipe-separated signals that fired: `asn`, `rdns`, `header` |
| confidence | TEXT | `high` (2+ signals) / `medium` (1 strong) / `low` |
| is_known_pinning | INT | 1 = dedicated IPFS pinning service |
| is_private_node | INT | 1 = not a known commercial provider |

### `tls_results`
| Column | Type | Description |
|---|---|---|
| cert_valid | INT | 1=valid, 0=invalid, NULL=no HTTPS |
| cert_issuer_org | TEXT | Certificate issuer (e.g. `Let's Encrypt`) |
| cert_expiry_iso | TEXT | ISO 8601 expiry date |
| cert_days_remaining | INT | Days until expiry (negative = already expired) |
| cert_is_expired | INT | 1 if expired |
| cert_expiring_soon | INT | 1 if expiring within `CERT_WARN_DAYS` |
| domain_http_status | INT | Final HTTP status after redirects |
| domain_redirects_to_ipfs | INT | 1 if final URL is an IPFS gateway |
| domain_final_url | TEXT | Final URL after all redirects |

### `agent_versions`
| Column | Type | Description |
|---|---|---|
| gateway | TEXT | Gateway URL that returned the version header |
| raw_agent | TEXT | Full raw string (e.g. `kubo/0.28.0/...`) |
| kubo_version | TEXT | Parsed semver (e.g. `0.28.0`) |
| version_major/minor/patch | INT | Parsed components |
| is_outdated | INT | 1 if older than `KUBO_MINIMUM_VERSION` |
| detection_src | TEXT | Header name: `Server`, `X-Ipfs-Version`, `Via` |

### `liveness_results`
| Column | Type | Description |
|---|---|---|
| cid | TEXT | IPFS CID being probed |
| gateway | TEXT | Gateway base URL |
| http_status | INT | HTTP response code |
| content_type | TEXT | Content-Type response header |
| content_length | INT | Content-Length if present |
| response_ms | REAL | Round-trip latency in milliseconds |
| is_live | INT | 1 if HTTP 2xx or 3xx |

### `dag_stats`
| Column | Type | Description |
|---|---|---|
| cid | TEXT | IPFS CID queried |
| size_bytes | INT | Total DAG payload size in bytes |
| num_blocks | INT | Number of unique blocks in the DAG |
| size_bucket | TEXT | `tiny` / `small` / `medium` / `large` |
| dag_error | TEXT | Error message if the RPC call failed |

### `provider_records`
| Column | Type | Description |
|---|---|---|
| cid | TEXT | IPFS CID queried |
| provider_count | INT | Unique peers announcing they provide the CID |
| peer_ids_json | TEXT | JSON array of peer ID strings (capped at 50) |
| has_pinning_svc | INT | 1 if a known pinning-service peer is in the provider list |
| pinning_svc_name | TEXT | Which service, if detected |

### `ipns_analysis`
| Column | Type | Description |
|---|---|---|
| ipns_key | TEXT | Full IPNS key string |
| key_type | TEXT | `ed25519` / `rsa_legacy` / `unknown` |
| declared_ttl | INT | TTL from the DNS record in seconds |

### `ens_results`
| Column | Type | Description |
|---|---|---|
| ens_name | TEXT | Queried ENS name (e.g. `example.eth`) |
| ens_cid | TEXT | CID decoded from ENS contenthash |
| dnslink_cid | TEXT | CID from the DNSLink record (for comparison) |
| cids_match | INT | 1 if ENS and DNSLink CIDs are equal |
| ens_error | TEXT | Reason if no ENS record was found |

### `longitudinal`
| Column | Type | Description |
|---|---|---|
| round_number | INT | Re-scan round (1 through `LONGITUDINAL_ROUNDS`) |
| cid_at_check | TEXT | CID observed in this round |
| cid_changed | INT | 1 if different from the round-0 baseline |
| is_live | INT | 1 if the `_dnslink` record still exists |
