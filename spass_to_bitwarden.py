#!/usr/bin/env python3
"""
Convert a Samsung Pass export (.spass) into a Bitwarden-importable CSV.

Usage:
    python3 spass_to_bitwarden.py path/to/export.spass [-o output.csv] [-s 5]

Writes the full CSV plus a <name>_bitwarden_sample5.csv with the first 5
logins, so you can test the Bitwarden import before importing everything.

You'll be prompted for the password you set when exporting from Samsung Pass.
In Bitwarden: Tools > Import data > format "Bitwarden (csv)" > pick the CSV.

The output CSV holds your passwords in plain text. Delete it after importing.

Format notes (.spass):
  file = base64( salt[20] | iv[16] | AES-256-CBC ciphertext )
  key  = PBKDF2-HMAC-SHA256(password, salt, 70000 iterations, 32 bytes)
  plaintext = version line, then tables separated by "next_table".
  Each table: a ';'-separated header, then rows of ';'-separated base64 fields.

No third-party packages or external tools needed: plain Python 3 only, and no
network access.
"""

import argparse
import base64
import binascii
import csv
import getpass
import hashlib
import os
import sys

SALT_LEN = 20
IV_LEN = 16
ITERATIONS = 70000

BITWARDEN_HEADER = [
    "folder", "favorite", "type", "name", "notes", "fields", "reprompt",
    "login_uri", "login_username", "login_password", "login_totp",
]


# ---------- decryption ----------
#
# AES-256-CBC decryption in pure Python, so the key never leaves this process
# (no subprocess, no command-line arguments visible to other users) and there
# is nothing to install. Exports are small, so speed is not a concern.

def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p


def _make_sbox():
    sbox = [0x63] * 256
    for a in range(1, 256):
        inv = next(b for b in range(1, 256) if _gmul(a, b) == 1)
        s = inv
        for shift in range(1, 5):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox[a] = s ^ 0x63
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_MUL = {m: [_gmul(x, m) for x in range(256)] for m in (9, 11, 13, 14)}


def _expand_key_256(key):
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - 8], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(15)]


def _decrypt_block(block, round_keys):
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    s = [b ^ k for b, k in zip(block, round_keys[14])]
    for rnd in range(13, -1, -1):
        # InvShiftRows + InvSubBytes (state is column-major: index = row + 4*col)
        s = [_INV_SBOX[s[r + 4 * ((c - r) % 4)]] for c in range(4) for r in range(4)]
        s = [b ^ k for b, k in zip(s, round_keys[rnd])]
        if rnd:
            out = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                out += [
                    m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3],
                    m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                    m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3],
                    m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3],
                ]
            s = out
    return s


def aes256_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) == 0 or len(data) % 16:
        raise ValueError("ciphertext is not a multiple of the block size")
    round_keys = _expand_key_256(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(block, round_keys), prev))
        prev = block
    pad = out[-1]
    if not 1 <= pad <= 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return bytes(out[:-pad])


def decrypt_spass(raw: bytes, password: str) -> str:
    try:
        blob = base64.b64decode(b"".join(raw.split()), validate=True)
    except (binascii.Error, ValueError):
        sys.exit("Not a valid .spass file (expected base64 content).")
    if len(blob) < SALT_LEN + IV_LEN + 16:
        sys.exit("Not a valid .spass file (too short).")
    salt, iv, ct = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN + IV_LEN], blob[SALT_LEN + IV_LEN:]
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, 32)
    try:
        return aes256_cbc_decrypt(key, iv, ct).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        sys.exit("Could not decrypt: wrong password or not a valid .spass file.")


# ---------- parsing ----------

def b64field(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return value
    return "" if decoded == "&&&NULL&&&" else decoded


def parse_tables(text: str):
    """Yield (header, rows) for each table; rows are dicts of decoded fields."""
    lines = text.replace("\r\n", "\n").split("\n")
    tables, current = [], []
    if lines and ";" not in lines[0]:
        lines = lines[1:]  # leading format-version line
    for line in lines:
        if line.strip() == "next_table":
            tables.append(current)
            current = []
        else:
            current.append(line)
    tables.append(current)

    for table in tables:
        table = [l for l in table if l.strip()]
        if not table:
            continue
        header = [h.strip() for h in table[0].split(";")]
        rows = []
        for line in table[1:]:
            values = [b64field(v) for v in line.split(";")]
            values += [""] * (len(header) - len(values))
            rows.append(dict(zip(header, values)))
        yield header, rows


def first(row, *keys):
    for k in keys:
        if row.get(k):
            return row[k]
    return ""


def login_uri(row):
    uri = first(row, "origin_url", "host_url", "action_url")
    if uri.startswith("android://"):
        package = uri[len("android://"):].split("@")[-1].strip("/")
        uri = "androidapp://" + package if package else ""
    if not uri and row.get("package_name"):
        uri = "androidapp://" + row["package_name"]
    return uri


def to_bitwarden(header, rows):
    cols = set(header)
    out = []
    if "password_value" in cols or "username_value" in cols:
        for r in rows:
            name = first(r, "title", "app_name") or login_uri(r) or "Samsung Pass login"
            out.append({
                "type": "login",
                "name": name,
                "notes": first(r, "credential_memo", "memo"),
                "login_uri": login_uri(r),
                "login_username": r.get("username_value", ""),
                "login_password": r.get("password_value", ""),
                "login_totp": first(r, "otp"),
            })
    elif "note_title" in cols or "note_detail" in cols:
        for r in rows:
            out.append({
                "type": "note",
                "name": r.get("note_title") or "Samsung Pass note",
                "notes": r.get("note_detail", ""),
            })
    else:
        # Cards, addresses, or anything else: keep everything as a secure note
        # so nothing is lost. Bitwarden's CSV import doesn't support cards.
        skip = {"_id", "reserved_1", "reserved_2", "reserved_3", "reserved_4", "reserved_5"}
        for r in rows:
            body = "\n".join(f"{k}: {v}" for k, v in r.items() if v and k not in skip)
            if not body:
                continue
            name = first(r, "card_name", "name_on_card", "full_name", "title", "name") or "Samsung Pass item"
            out.append({"type": "note", "name": name, "notes": body})
    return out


# ---------- main ----------

def write_csv(path, items):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=BITWARDEN_HEADER)
        w.writeheader()
        for item in items:
            w.writerow({k: item.get(k, "") for k in BITWARDEN_HEADER})


def inspect(text):
    """Show the export's layout without revealing any stored values."""
    first_line = text.split("\n", 1)[0]
    print(f"first line: {first_line[:20]!r}" if ";" not in first_line else "first line: (table header)")
    for n, (header, rows) in enumerate(parse_tables(text), 1):
        kind = to_bitwarden(header, rows[:1])
        kind = kind[0]["type"] if kind else "empty"
        print(f"\ntable {n}: {len(rows)} rows, converted as: {kind}")
        for col in header:
            filled = sum(1 for r in rows if r.get(col))
            print(f"  {col:<28} filled in {filled}/{len(rows)} rows")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spass", help="path to the .spass export")
    ap.add_argument("-o", "--output", help="output CSV (default: <name>_bitwarden.csv next to the .spass)")
    ap.add_argument("-p", "--password",
                    help="export password (prompted if omitted; avoid, it is visible in shell history and ps)")
    ap.add_argument("-s", "--sample", type=int, default=5,
                    help="also write a CSV with only the first N logins for a test import (default 5, 0 = off)")
    ap.add_argument("--inspect", action="store_true",
                    help="print the structure (tables, column names, row counts, which columns are filled) "
                         "without any values, and write nothing")
    args = ap.parse_args()

    with open(args.spass, "rb") as f:
        raw = f.read()
    password = args.password or getpass.getpass("Samsung Pass export password: ")
    text = decrypt_spass(raw, password)

    if args.inspect:
        inspect(text)
        return

    items = []
    for header, rows in parse_tables(text):
        items.extend(to_bitwarden(header, rows))

    base = os.path.splitext(os.path.basename(args.spass))[0]
    output = args.output or os.path.join(
        os.path.dirname(os.path.abspath(args.spass)), base + "_bitwarden.csv",
    )
    write_csv(output, items)
    logins = sum(1 for i in items if i["type"] == "login")
    print(f"Wrote {len(items)} items ({logins} logins, {len(items) - logins} notes) to {output}")

    if args.sample > 0:
        sample = [i for i in items if i["type"] == "login"][:args.sample]
        sample_output = os.path.splitext(output)[0] + f"_sample{args.sample}.csv"
        write_csv(sample_output, sample)
        print(f"Wrote {len(sample)} logins to {sample_output} (test import)")

    print("Import in Bitwarden as 'Bitwarden (csv)', then delete these files.")


if __name__ == "__main__":
    main()
