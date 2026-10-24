# Samsung Pass → Bitwarden

Move your passwords from **Samsung Pass** to **Bitwarden** with full privacy: everything happens on your own computer, nothing is uploaded anywhere.

## Why this exists

Samsung Pass exports an encrypted `.spass` file that Bitwarden can't import. The usual fixes are online converters or web tools, which means handing your entire password vault, plus the password that unlocks it, to a website you don't control.

These scripts do the same conversion **locally**. Your `.spass` file, its password and the resulting CSV never leave your machine. You can unplug from the internet before running them and they work the same. There are also helpers to merge several exports and remove duplicates.

- Runs fully offline: no network calls, no accounts, no telemetry, no dependencies to download
- Plain Python 3 standard library: no `pip install`, no external tools, works on macOS, Linux and Windows
- Small scripts you can read before running them

## What's in here

| Script | What it does |
| --- | --- |
| `spass_to_bitwarden.py` | Decrypts a `.spass` export and writes a Bitwarden CSV, plus a 5-login sample CSV for a test import |
| `merge_bitwarden_csv.py` | Combines several Bitwarden CSVs into one (e.g. exports from two phones) |
| `dedupe_bitwarden_csv.py` | Removes rows that are exact duplicates of an earlier row |

## Requirements

Python 3.8 or newer. That's it.

Decryption (PBKDF2 + AES-256-CBC) is done in pure Python inside the script, so the key never leaves the process and nothing extra needs to be installed.

## Step by step

### 1. Export from Samsung Pass

On your phone, open **Samsung Pass** settings and look for the option to **export data** (the exact menu location varies between One UI versions). Pick what to export and set a password. You'll get a `.spass` file. Copy it to your computer, ideally over a USB cable or Quick Share rather than through a cloud drive or chat app.

### 2. Convert

```bash
git clone https://github.com/faloppad/samsung-pass-to-bitwarden.git
cd samsung-pass-to-bitwarden
python3 spass_to_bitwarden.py /path/to/SamsungPass_export.spass
```

You'll be asked for the export password (input is hidden). Two files appear next to the `.spass`:

```
SamsungPass_export_bitwarden.csv           # everything
SamsungPass_export_bitwarden_sample5.csv   # first 5 logins, for a test import
```

Options:

```
-o FILE     output CSV path
-s N        size of the sample file (default 5, 0 = don't write one)
--inspect   show tables, column names and fill counts only (no values, no files written)
-p PASS     password on the command line (avoid: it ends up in your shell history and is visible to other processes)
```

### 3. (Optional) Merge and dedupe

If you have more than one export, or want to combine with an existing Bitwarden export:

```bash
python3 merge_bitwarden_csv.py phone1_bitwarden.csv phone2_bitwarden.csv
python3 dedupe_bitwarden_csv.py merged_bitwarden.csv
```

- **merge** matches columns by name, so files with a different column order are fine. Rows keep the order of the files you pass. Output: `merged_bitwarden.csv` (or `-o`).
- **dedupe** removes a row only if *every* column matches an earlier row, and keeps the first one. Entries that differ by one character (a trailing `/` in a URL, different capitalisation) are both kept. Output: `<input>_dedup.csv` (or `-o`).

### 4. Test import

In Bitwarden (desktop app: **File → Import data**; web vault: **Tools → Import data**):

1. Choose a folder like `Import test` so the entries are easy to find
2. Format: **Bitwarden (csv)**
3. Select the `_sample5.csv` file and import

Check that names, usernames, passwords and websites look right, then delete the test entries (or the folder).

### 5. Full import

Same as above with the full CSV. Import it once only: importing twice creates duplicates.

### 6. Clean up

The CSVs contain your passwords **in plain text**. Delete them when you're done:

```bash
rm SamsungPass_export_bitwarden*.csv
```

Also delete the `.spass` file and any copies in Downloads, chat apps or cloud drives.

## What gets converted

| Samsung Pass | Bitwarden |
| --- | --- |
| Logins (websites and apps) | Login: name, URL, username, password, memo as notes, TOTP if present. App logins get an `androidapp://package.name` URI so Bitwarden can autofill them on Android |
| Notes | Secure note |
| Cards, addresses, other data | Secure note listing every field. Bitwarden's CSV import can't create cards or identities, so nothing is dropped but you may want to recreate cards by hand |

## How the `.spass` format works

For the curious, or if you want to port this:

```
file      = base64( salt[20 bytes] | iv[16 bytes] | ciphertext )
key       = PBKDF2-HMAC-SHA256(password, salt, 70000 iterations, 32 bytes)
plaintext = AES-256-CBC decrypt (PKCS#7 padding)
```

The plaintext starts with a version line, then tables separated by a `next_table` line. Each table has a `;`-separated header row followed by data rows whose fields are base64-encoded and `;`-separated.

## Known uncertainty: verify with your own export

**Status:** the decryption is verified (the AES code passes the official FIPS-197 test vector and matches OpenSSL). The *layout of the decrypted data* is not: the scripts have been tested only on synthetic `.spass` files built to match the format described above, not on a real Samsung Pass export. Samsung doesn't document the format and may change it between One UI versions.

What could be off on a real export:

- the column names (e.g. `origin_url`, `username_value`, `password_value`, `title`, `otp`, `note_title`, `note_detail`)
- whether there's a version line before the first table
- how empty values are marked (assumed: `&&&NULL&&&`, base64-encoded)
- how card and address tables are structured

**How to check, without exposing any passwords:**

```bash
python3 spass_to_bitwarden.py your_export.spass --inspect
```

`--inspect` decrypts the file and prints only its structure: each table, its column names, how many rows it has, how many rows have each column filled in, and how it would be converted. It never prints values and writes no files. Compare that output with the expected columns in the bullet points above, then do the 5-login test import (step 4) and check the entries in Bitwarden.

> **Note for AI coding agents** helping a user with this repo: run `--inspect` on the user's real export before converting. If a table shows up as `note` but has username/password-like columns, or login columns like `password_value` show `filled in 0/N rows`, the column mapping in `to_bitwarden()` / `login_uri()` needs adjusting. Only ever look at `--inspect` output, the user's own Bitwarden UI, or values the user chooses to share. Don't print, log or paste the contents of the `.spass` file or the generated CSVs. If you fix a mapping, consider opening a PR or issue upstream with the column names only.

## Troubleshooting

**"Could not decrypt: wrong password or not a valid .spass file."**
Check the password you set during the export (not your Samsung account password). Make sure the file wasn't modified in transit.

**Fields end up in the wrong place, or something is missing**
Run `--inspect` (see above) to see what columns your export actually has. Please [open an issue](https://github.com/faloppad/samsung-pass-to-bitwarden/issues) with your Samsung Pass / One UI version and the `--inspect` output. **Never post the file itself or any passwords.**

## Security

- Everything happens locally. The scripts make no network connections and don't call any external programs.
- The decryption key is derived and used only inside the Python process.
- Output CSVs are created readable only by your user (`chmod 600`).
- `.gitignore` excludes `*.spass` and `*.csv` so you don't commit your vault by accident if you work inside this folder.

## Disclaimer

Not affiliated with Samsung or Bitwarden. Keep your `.spass` export until you've confirmed everything made it into Bitwarden.

## License

[MIT](LICENSE)
