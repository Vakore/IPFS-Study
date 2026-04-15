#!/usr/bin/env python3
"""
01_fetch_domains.py  —  Download the Tranco top-1M list and load it into the DB.

Run once at the start of the study.  Safe to re-run; already-imported domains
are skipped via INSERT OR IGNORE.

Usage:
    python 01_fetch_domains.py
    python 01_fetch_domains.py --sample 10000   # test with smaller slice
    python 01_fetch_domains.py --custom my_list.txt
"""

import argparse
import csv
import io
import os
import sys
import zipfile

import requests
from tqdm import tqdm

import db
from config import (
    DOMAIN_LIST_URL,
    DOMAIN_LIST_PATH,
    DOMAIN_SAMPLE_SIZE,
    CUSTOM_DOMAIN_LIST,
)

# ---------------------------------------------------------------------------

def download_tranco(url: str, dest: str) -> None:
    """Stream-download the Tranco zip with a progress bar."""
    print(f"[01] Downloading domain list from {url} …")
    r = requests.get(url, stream=True, timeout=60)
    r.raise_for_status()
    total = int(r.headers.get("content-length", 0))
    with open(dest, "wb") as f, tqdm(
        total=total, unit="B", unit_scale=True, desc="Downloading"
    ) as pbar:
        for chunk in r.iter_content(chunk_size=65536):
            f.write(chunk)
            pbar.update(len(chunk))
    print(f"[01] Saved → {dest}")


def iter_tranco_zip(path: str, limit: int):
    """Yield (rank, domain) pairs from the Tranco zip file."""
    with zipfile.ZipFile(path) as zf:
        name = zf.namelist()[0]          # top-1m.csv inside the zip
        with zf.open(name) as raw:
            reader = csv.reader(io.TextIOWrapper(raw, encoding="utf-8"))
            for i, row in enumerate(reader, start=1):
                if limit and i > limit:
                    break
                if len(row) >= 2:
                    rank, domain = int(row[0]), row[1].strip().lower()
                    if domain:
                        yield rank, domain


def iter_custom_list(path: str, limit: int):
    """Yield (rank, domain) from a plain-text file (one domain per line)."""
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            if limit and i > limit:
                break
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                yield i, domain


def load_into_db(source, limit: int) -> int:
    """Insert domains into the database; return count inserted."""
    db.init_db()
    inserted = 0
    batch, BATCH_SIZE = [], 2000

    def flush(batch):
        with db.get_db() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO domains (domain, rank) VALUES (?, ?)",
                batch,
            )
        return len(batch)

    with tqdm(desc="Importing domains", unit=" domains") as pbar:
        for rank, domain in source:
            batch.append((domain, rank))
            if len(batch) >= BATCH_SIZE:
                inserted += flush(batch)
                pbar.update(len(batch))
                batch = []

        if batch:
            inserted += flush(batch)
            pbar.update(len(batch))

    return inserted


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Fetch and import domain list")
    parser.add_argument("--sample",  type=int, default=DOMAIN_SAMPLE_SIZE,
                        help="Max domains to import (0 = all)")
    parser.add_argument("--custom",  type=str, default=CUSTOM_DOMAIN_LIST,
                        help="Path to a plain-text domain list (skip download)")
    parser.add_argument("--redownload", action="store_true",
                        help="Force re-download even if cache exists")
    args = parser.parse_args()

    limit = args.sample or 0  # 0 means unlimited

    if args.custom:
        if not os.path.exists(args.custom):
            sys.exit(f"[01] Custom list not found: {args.custom}")
        print(f"[01] Using custom domain list: {args.custom}")
        source = iter_custom_list(args.custom, limit)
    else:
        if not os.path.exists(DOMAIN_LIST_PATH) or args.redownload:
            download_tranco(DOMAIN_LIST_URL, DOMAIN_LIST_PATH)
        else:
            print(f"[01] Using cached list: {DOMAIN_LIST_PATH}")
        source = iter_tranco_zip(DOMAIN_LIST_PATH, limit)

    n = load_into_db(source, limit)
    print(f"[01] Done — {n:,} domains imported (new rows only).")


if __name__ == "__main__":
    main()
