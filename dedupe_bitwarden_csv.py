#!/usr/bin/env python3
"""
Remove exact duplicate rows from a Bitwarden CSV.

A row counts as a duplicate only if every column is identical to an earlier
row (name, notes, login_uri, login_username, login_password, ...). The first
occurrence is kept and the original order is preserved.

Usage:
    python3 dedupe_bitwarden_csv.py input.csv [-o output.csv]

Default output: <input>_dedup.csv next to the input file.
"""

import argparse
import csv
import os
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="Bitwarden CSV to clean")
    ap.add_argument("-o", "--output", help="output CSV (default: <input>_dedup.csv)")
    args = ap.parse_args()

    with open(args.csv, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            sys.exit(f"{args.csv} is empty")
        rows = list(reader)

    seen = set()
    kept = []
    for row in rows:
        key = tuple(row)
        if key in seen:
            continue
        seen.add(key)
        kept.append(row)

    output = args.output or os.path.splitext(args.csv)[0] + "_dedup.csv"
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(kept)

    print(f"{len(rows)} rows in, {len(rows) - len(kept)} duplicates removed, {len(kept)} rows written to {output}")


if __name__ == "__main__":
    main()
