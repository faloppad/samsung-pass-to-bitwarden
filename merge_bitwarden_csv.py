#!/usr/bin/env python3
"""
Merge several Bitwarden CSVs into one.

Rows are appended in the order the files are given. Columns are matched by
name, so files with a different column order (or extra columns) merge fine;
missing columns are left empty. Nothing is deduplicated here, run
dedupe_bitwarden_csv.py on the result for that.

Usage:
    python3 merge_bitwarden_csv.py a.csv b.csv [c.csv ...] [-o merged.csv]

Default output: merged_bitwarden.csv next to the first input file.
"""

import argparse
import csv
import os

BITWARDEN_HEADER = [
    "folder", "favorite", "type", "name", "notes", "fields", "reprompt",
    "login_uri", "login_username", "login_password", "login_totp",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvs", nargs="+", help="Bitwarden CSVs to merge")
    ap.add_argument("-o", "--output", help="output CSV (default: merged_bitwarden.csv)")
    args = ap.parse_args()

    output = args.output or os.path.join(
        os.path.dirname(os.path.abspath(args.csvs[0])), "merged_bitwarden.csv",
    )
    if any(os.path.abspath(p) == os.path.abspath(output) for p in args.csvs):
        ap.error(f"output {output} is also an input; pick another name with -o")

    header = list(BITWARDEN_HEADER)
    rows = []
    for path in args.csvs:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for col in reader.fieldnames or []:
                if col not in header:
                    header.append(col)
            file_rows = list(reader)
        extra = sum(1 for r in file_rows if None in r)
        if extra:
            print(f"warning: {extra} rows in {path} have more values than columns; extra values dropped")
        rows.extend(file_rows)
        print(f"{len(file_rows):>6} rows from {path}")

    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=header, restval="")
        w.writeheader()
        for row in rows:
            w.writerow({k: (v or "") for k, v in row.items() if k is not None})

    print(f"{len(rows):>6} rows written to {output}")


if __name__ == "__main__":
    main()
