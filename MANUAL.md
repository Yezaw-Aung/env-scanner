# env-guard — User Manual

A detailed guide to installing and using env-guard for detecting and
extracting hardcoded secrets from your source code.

---

## 1. Requirements and Supported Environment

| Requirement | Detail |
|---|---|
| Python | 3.8 or newer |
| OS | macOS, Linux, or Windows (any platform with Python) |
| Dependencies | None — uses only the Python standard library |
| Network | Not required — runs entirely offline |

---

## 2. Installation

```bash
git clone https://github.com/Yezaw-Aung/env-scanner.git
cd env-scanner
```

No `pip install` step is needed. Verify the tool runs:

```bash
python3 -m src.main --help
```

You should see the help text listing all available options.

---

## 3. Modes Overview

env-guard has two modes:

| Mode | Flag | Description |
|---|---|---|
| **Scan-only** | _(default, no flag)_ | Reports all detected secret candidates. Does not modify any files. |
| **Refactor** | `-r` or `--refactor` | Interactively prompts for each finding. Confirmed secrets are written to `.env` and the source file is rewritten to use environment variables. |

---

## 4. Scan-Only Mode (Default)

### Basic Usage

```bash
python3 -m src.main <directory>
```

### What It Does

1. Recursively walks the target directory.
2. Skips ignored directories (`node_modules`, `venv`, `dist`, `build`,
   `generated`, `.git`, caches, etc.) and ignored file types (images,
   binaries, `.env`, lockfiles, SVGs, source maps).
3. For each source file, extracts string literals and evaluates them using
   three detectors:
   - **Variable-name pattern**: is the string assigned to a variable whose
     name contains a secret keyword (`secret`, `token`, `password`,
     `api_key`, `aws_secret`, `jwt`, `database_url`, etc.)?
   - **Value-format regex**: does the value match a known credential format
     (AWS `AKIA…`, Stripe `sk_live_…`, GitHub `ghp_…`, Slack `xox…`,
     Google `AIza…`)?
   - **Shannon entropy**: is the string high-entropy (> 4.5 by default) and
     not filtered as a false positive (CSS, Tailwind, template literals,
     prose, localhost URLs, multi-line strings)?
4. Prints a styled report for each finding.

### Output Fields

Each finding displays:

| Field | Meaning |
|---|---|
| **File** | Relative path and line number of the finding |
| **String** | The matched string literal (truncated if > 120 chars) |
| **Entropy** | Shannon entropy score (0–~6) |
| **Reason** | Why it was flagged: `Suspicious variable name`, `Known credential format`, or `High Shannon entropy` |
| **Variable** | The variable name the string was assigned to, if detected |

### Summary Report

At the end, a summary is printed:

```text
======================================================================
SCAN COMPLETED
======================================================================
Mode: Scan-only
Files Scanned with Findings: 3
Total Secret Candidates Flagged: 7
======================================================================
```

---

## 5. Refactor Mode (`-r` / `--refactor`)

### Basic Usage

```bash
python3 -m src.main <directory> -r
```

### What It Does

For each finding, the tool prompts:

```text
Is this a secret credential? (y/n) [suggested: JWT_SECRET]:
```

- If you press **y** + Enter:
  1. You are prompted for a variable name (a suggestion is pre-filled from
     the source code variable name — press Enter to accept).
  2. The secret is appended to the `.env` file as `VAR_NAME="secret_value"`.
  3. The source file is rewritten: the hardcoded string is replaced with
     `os.environ.get('VAR_NAME')` (Python) or `process.env.VAR_NAME` (JS/TS).
  4. For Python files, `import os` is automatically added if not present.
- If you press **n** + Enter: the finding is skipped. Subsequent occurrences
  of the same value are also skipped silently.

### Duplicate Handling

If the same secret value appears in multiple files and you confirmed it once,
all subsequent occurrences are auto-refactored without prompting.

### Options

| Flag | Description |
|---|---|
| `-e, --env <path>` | Specify a custom `.env` file path (default: `<target_dir>/.env`) |
| `-d, --duplicate` | Copy the target directory to `<dir>_env_guard_fixed` and operate on the copy. The original files remain untouched. |

### Example with All Options

```bash
python3 -m src.main my-project -r -d -e /home/user/.env.production
```

This copies `my-project` to `my-project_env_guard_fixed`, scans the copy,
writes secrets to `/home/user/.env.production`, and refactors files in the
copy.

---

## 6. Tuning Detection Sensitivity

### Entropy Threshold (`-t` / `--threshold`)

Default: **4.5**. Lower values = more sensitive (more false positives).
Higher values = less sensitive (may miss some secrets).

```bash
# More sensitive (catches shorter/weaker tokens)
python3 -m src.main my-project -t 3.5

# Less sensitive (only very random-looking strings)
python3 -m src.main my-project -t 5.0
```

### Minimum String Length (`-l` / `--min-len`)

Default: **8**. Strings shorter than this are skipped.

```bash
# Catch shorter secrets (e.g., 6-char API keys)
python3 -m src.main my-project -l 6
```

---

## 7. Input File Format

env-guard does not use a structured input file. It scans **source code
directories** directly. It reads any text file (UTF-8) and looks for string
literals in:

- Single quotes: `'...'`
- Double quotes: `"..."`
- Triple quotes: `"""..."""` and `'''...'''`
- Backticks (template literals): `` `...` ``

Files that cannot be decoded as UTF-8 (binary files) are silently skipped.

### Supported File Types for Refactoring

| Language | Extensions | Replacement Pattern |
|---|---|---|
| Python | `.py` | `os.environ.get('VAR_NAME')` |
| JavaScript | `.js`, `.jsx` | `process.env.VAR_NAME` |
| TypeScript | `.ts`, `.tsx` | `process.env.VAR_NAME` |

Scanning (detection only) works on any text file regardless of language.

---

## 8. Skipped Directories and File Types

### Directories Skipped

| Category | Examples |
|---|---|
| Version control | `.git`, `.hg`, `.svn` |
| Dependencies | `node_modules`, `venv`, `.venv`, `vendor`, `bower_components` |
| Build outputs | `dist`, `build`, `out`, `target`, `release`, `.next`, `.nuxt` |
| Generated code | `generated`, `__generated__`, `.prisma` |
| Caches | `.cache`, `.turbo`, `.gradle`, `__pycache__`, `.pytest_cache` |
| Coverage | `coverage`, `.nyc_output` |
| IDE | `.idea`, `.vscode` |

### File Types Skipped

Images (`.png`, `.jpg`, `.svg`, …), binaries (`.exe`, `.dll`, `.so`, …),
fonts (`.woff`, `.ttf`, …), media (`.mp4`, `.mp3`, …), databases
(`.db`, `.sqlite`), lockfiles (`.lock`), source maps (`.map`), and more.

---

## 9. Troubleshooting

### "Directory does not exist"

```text
Error: Directory 'my-project' does not exist.
```

**Cause**: The path you provided is wrong.
**Fix**: Use an absolute or correct relative path. Check with `ls`.

### "is not a directory"

```text
Error: 'config.py' is not a directory.
```

**Cause**: You pointed the tool at a file, not a directory.
**Fix**: Pass the parent directory: `python3 -m src.main .` or
`python3 -m src.main ./src`.

### No findings but you know there are secrets

**Possible causes**:
1. The secret is inside a comment — env-guard skips comments by design.
2. The secret is in a `.env` file or other ignored file — these are skipped.
3. The string is shorter than `--min-len` (default 8) — try `-l 6`.
4. The entropy is below the threshold — try `-t 3.5`.
5. The file is in an ignored directory (e.g., `node_modules`).

### Too many false positives

**Fix**: Raise the entropy threshold: `python3 -m src.main my-project -t 5.0`.
The variable-name and value-pattern detectors will still run, but fewer
entropy-based findings will appear.

### Refactor mode doesn't modify files

**Cause**: The file extension is not supported for refactoring (only `.py`,
`.js`, `.jsx`, `.ts`, `.tsx`). Or the match text was not found (the file may
have been modified since the scan).

### `--duplicate` has no effect

```text
[!] --duplicate has no effect without --refactor
```

**Cause**: You used `-d` without `-r`. Scan-only mode doesn't modify files,
so duplicating the directory is unnecessary.
**Fix**: Add `-r` if you want to refactor: `python3 -m src.main my-project -r -d`.

---

## 10. Complete Worked Example

### Step 1: Scan the sample project

```bash
python3 -m src.main examples/js-ts-api-keys
```

### Output

```text
======================================================================
🛡️  ENV-GUARD: Cybersecurity Hardcoded Secret Scanner & Refactorer  🛡️
======================================================================

Mode: Scan-only
Target Directory: /path/to/examples/js-ts-api-keys
Entropy Threshold: 4.5
Min String Length: 8
Scanning files recursively...

[⚠️  CRITICAL] Potential secret detected!
  File: credentials.js:5
  String: "AKIAIOSFODNN7EXAMPLE"
  Entropy: 3.679
  Reason: Suspicious variable name
  Variable: AWS_ACCESS_KEY_ID

[⚠️  CRITICAL] Potential secret detected!
  File: credentials.js:6
  String: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  Entropy: 4.664
  Reason: Suspicious variable name
  Variable: AWS_SECRET_ACCESS_KEY

[⚠️  CRITICAL] Potential secret detected!
  File: credentials.js:9
  String: "sk_live_51Mza2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"
  Entropy: 5.091
  Reason: Suspicious variable name
  Variable: STRIPE_SECRET_KEY

[⚠️  CRITICAL] Potential secret detected!
  File: frontend-config.ts:5
  String: "AIzaSyDemo_99887766aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
  Entropy: 5.215
  Reason: Suspicious variable name
  Variable: GOOGLE_MAPS_API_KEY

[⚠️  CRITICAL] Potential secret detected!
  File: frontend-config.ts:8
  String: "pk_live_51Mza2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"
  Entropy: 5.091
  Reason: Suspicious variable name
  Variable: STRIPE_PUBLISHABLE_KEY

[⚠️  CRITICAL] Potential secret detected!
  File: frontend-config.ts:11
  String: "AIzaSyFirebase_99887766_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234"
  Entropy: 5.245
  Reason: Suspicious variable name
  Variable: FIREBASE_API_KEY

======================================================================
SCAN COMPLETED
======================================================================
Mode: Scan-only
Files Scanned with Findings: 2
Total Secret Candidates Flagged: 6
======================================================================
```

### Step 2: Refactor on a duplicate copy

```bash
python3 -m src.main examples/js-ts-api-keys -r -d
```

The tool prompts for each finding. Type `y` + Enter to confirm, then
accept the suggested variable name by pressing Enter.

After confirming all 6 findings:

- A copy is created at `examples/js-ts-api-keys_env_guard_fixed/`.
- A `.env` file is created with all 6 secrets.
- Each source file is rewritten to use `process.env.VAR_NAME`.
- The original `examples/js-ts-api-keys/` remains untouched.

---

## 11. Running the Test Suite

```bash
python3 -m unittest tests.test_env_guard tests.test_real_mistakes -v
```

This runs 26 tests covering:

- Shannon entropy calculation
- String candidate extraction
- Secret variable-name detection (positive and negative cases)
- Known credential-format detection (AWS, Stripe, GitHub, Slack, Google)
- Comment skipping (hash, slash, block, inline)
- CSS/Tailwind false-positive filtering
- Template literal and multi-line filtering
- Non-secret variable-name suppression
- Scan-only mode (no file modification)
- Refactor mode with duplicate directory
- End-to-end flow with real-world fixture files
