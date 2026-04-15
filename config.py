# =============================================================================
# config.py  —  IPFS Field Study: Central Configuration  (v2)
# =============================================================================

import os

# ---------------------------------------------------------------------------
# 1. Domain Lists
# ---------------------------------------------------------------------------
DOMAIN_LIST_URL    = "https://tranco-list.eu/top-1m.csv.zip"
DOMAIN_LIST_PATH   = "tranco_top1m.csv.zip"
DOMAIN_SAMPLE_SIZE = 50_000   # 0 = all; use 5_000 for first test run
CUSTOM_DOMAIN_LIST = None     # e.g. "my_domains.txt"

# ---------------------------------------------------------------------------
# 2. Rate Limiting
# ---------------------------------------------------------------------------
DNS_QPS  = 40    # queries/sec for DNS resolution
IPFS_RPS = 5     # requests/sec to IPFS gateways
GEO_RPS  = 10    # requests/sec to geo API
TLS_RPS  = 10    # TLS / domain HTTP checks per second

# ---------------------------------------------------------------------------
# 3. DNS / DNSSEC
# ---------------------------------------------------------------------------
RESOLVERS = [
    "1.1.1.1",   # Cloudflare  (DNSSEC-validating)
    "8.8.8.8",   # Google
    "9.9.9.9",   # Quad9       (DNSSEC-validating)
]
DNS_TIMEOUT  = 5
DNS_LIFETIME = 10
EDNS_PAYLOAD = 4096

# ---------------------------------------------------------------------------
# 4. zdns (optional fast-path scanner)
# ---------------------------------------------------------------------------
# go install github.com/zmap/zdns@latest  →  add ~/go/bin to PATH
USE_ZDNS     = True
ZDNS_THREADS = 1000
ZDNS_TIMEOUT = 5

# ---------------------------------------------------------------------------
# 5. IPFS Gateways (liveness checks)
# ---------------------------------------------------------------------------
IPFS_GATEWAYS = [
    "https://cloudflare-ipfs.com/ipfs/",
    "https://ipfs.io/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
    "https://dweb.link/ipfs/",
]
GATEWAY_TIMEOUT = 15

# ---------------------------------------------------------------------------
# 6. Geo / ASN lookup  (ip-api.com)
# ---------------------------------------------------------------------------
GEO_API_KEY = os.environ.get("IP_API_KEY", None)   # Pro key unlocks HTTPS

# ---------------------------------------------------------------------------
# 7. Agent version / Kubo currency
# ---------------------------------------------------------------------------
# Kubo versions STRICTLY OLDER than this tuple are flagged outdated.
# Update this before each study run to the current stable release.
KUBO_MINIMUM_VERSION = (0, 26, 0)   # (major, minor, patch)

# ---------------------------------------------------------------------------
# 8. Pinning-service fingerprints
# ---------------------------------------------------------------------------
# For each service, list lowercase substrings matched against:
#   "asn"     → ASN name string from ip-api
#   "rdns"    → reverse-DNS hostname of the IP
#   "headers" → HTTP response header keys (lowercase)
PINNING_SERVICES = {
    "Cloudflare": {
        "asn":     ["cloudflare"],
        "rdns":    ["cloudflare.com", ".cf."],
        "headers": ["cf-ray", "cf-cache-status"],
    },
    "Pinata": {
        "asn":     ["pinata"],
        "rdns":    ["pinata.cloud", "pinata.io"],
        "headers": ["x-pinata"],
    },
    "Infura": {
        "asn":     ["infura", "consensys"],
        "rdns":    ["infura.io"],
        "headers": ["x-infura-ipfs"],
    },
    "Fleek": {
        "asn":     ["fleek"],
        "rdns":    ["fleek.co", "on.fleek"],
        "headers": ["x-fleek"],
    },
    "Web3.Storage": {
        "asn":     ["protocol labs", "storacha"],
        "rdns":    ["web3.storage", "storacha.network"],
        "headers": ["x-web3-"],
    },
    "Filebase": {
        "asn":     ["filebase"],
        "rdns":    ["filebase.io"],
        "headers": ["x-filebase"],
    },
    "4EVERLAND": {
        "asn":     ["4everland"],
        "rdns":    ["4everland.io"],
        "headers": ["x-4ever"],
    },
}

# Large cloud/hosting providers — NOT pinning services.
# Used to distinguish "cloud-hosted private node" from "residential node".
CLOUD_PROVIDERS = {
    "AWS":          ["amazon", "aws"],
    "Google Cloud": ["google"],
    "Azure":        ["microsoft", "azure"],
    "Hetzner":      ["hetzner"],
    "DigitalOcean": ["digitalocean"],
    "Linode":       ["linode", "akamai"],
    "OVH":          ["ovh"],
    "Vultr":        ["vultr"],
    "Leaseweb":     ["leaseweb"],
}

# ---------------------------------------------------------------------------
# 9. TLS / domain HTTP check
# ---------------------------------------------------------------------------
TLS_TIMEOUT    = 10   # seconds for SSL handshake
HTTP_TIMEOUT   = 10   # seconds for plain domain HTTP probe
CERT_WARN_DAYS = 30   # flag certs expiring within N days

# ---------------------------------------------------------------------------
# 10. Local Kubo RPC  (script 08_kubo_rpc.py)
# ---------------------------------------------------------------------------
KUBO_API_BASE      = "http://localhost:5001/api/v0"
KUBO_TIMEOUT       = 30   # seconds per RPC call
KUBO_MAX_PROVIDERS = 100  # max peers returned by FindProviders

# ---------------------------------------------------------------------------
# 11. ENS cross-reference  (script 09_extended.py)
# ---------------------------------------------------------------------------
ENABLE_ENS        = True   # set False to skip ENS queries
ETH_RPC_URL       = "https://cloudflare-eth.com"
ETH_RPC_TIMEOUT   = 10
ENS_REGISTRY_ADDR = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"

# ---------------------------------------------------------------------------
# 12. Longitudinal scanning
# ---------------------------------------------------------------------------
LONGITUDINAL_ROUNDS         = 7
LONGITUDINAL_INTERVAL_HOURS = 24
LONGITUDINAL_STATE_FILE     = "longitudinal_state.json"

# ---------------------------------------------------------------------------
# 13. Database & output
# ---------------------------------------------------------------------------
DB_PATH             = "ipfs_study.db"
ANALYSIS_OUTPUT_DIR = "analysis_output"
