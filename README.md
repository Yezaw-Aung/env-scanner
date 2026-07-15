# env-guard

> **A CLI tool that scans your codebase for hardcoded secrets and helps you extract them into environment variables.**

---

## The Security Problem

Developers—especially beginners—frequently hardcode API keys, JWT secrets,
database passwords, AWS credentials, and other secrets directly in source
files. These secrets then get committed to version control, pushed to public
repositories, and exposed to anyone who reads the code. This is one of the
most common causes of cloud account compromise and data breaches.

**env-guard** scans a project directory for hardcoded secrets using three
complementary detection strategies, reports exactly where they are, and
optionally helps you refactor them out into a `.env` file.

---

## Who Should Use It

- **Students and junior developers** who want to check their projects before
  pushing to GitHub.
- **Team leads and reviewers** who want a quick audit of a codebase during
  code review.
- **CTF players and security learners** studying how secrets hide in code.
- **Anyone** who maintains a codebase and wants to catch leaked credentials
  before they become a incident.

---

## What It Does

- Recursively scans source files for string literals that look like secrets.
- Uses **three detection strategies**:
  1. **Variable-name pattern matching** — flags strings assigned to
     suspiciously named variables (`JWT_SECRET`, `AWS_SECRET_ACCESS_KEY`,
     `DATABASE_URL`, `API_KEY`, etc.).
  2. **Known credential-format regex** — flags values matching well-known
     formats (AWS `AKIA…` key IDs, Stripe `sk_live_…`, GitHub `ghp_…`,
     Slack `xox…`, Google `AIza…`).
  3. **Shannon entropy analysis** — flags high-entropy strings that resemble
     random tokens, base64 blobs, or hashes.
- Skips comments (`#`, `//`, `/* */`, `<!-- -->`) so commented-out code
  is not flagged.
- Filters out common false positives: CSS class lists, Tailwind utility
  strings, template literals with interpolation, multi-line prose, localhost
  URLs, SVG/asset files.
- **Scan-only mode** (default): reports all findings without modifying files.
- **Refactor mode** (`-r`): interactively prompts for each finding, writes
  confirmed secrets to a `.env` file, and rewrites source code to read from
  environment variables (`os.environ.get()` in Python, `process.env.` in
  JS/TS).
- Automatically skips dependency directories (`node_modules`, `venv`),
  build outputs (`dist`, `build`, `out`, `.next`), generated code
  (`generated`, `.prisma`), caches, and binary/asset files.

## What It Does NOT Do

- It does **not** send your code or secrets anywhere. Everything runs locally.
- It does **not** connect to any API, database, or network service.
- It does **not** modify files unless you explicitly pass `--refactor` and
  confirm each finding interactively.
- It does **not** detect secrets inside binary files, encrypted archives, or
  environment files (`.env` is deliberately skipped).
- It is **not** a substitute for proper secret management (Vault, AWS Secrets
  Manager, etc.). It is a first-pass audit tool.

---

## Installation

**Prerequisites**: Python 3.8 or newer. No external packages required.

```bash
git clone https://github.com/Yezaw-Aung/env-scanner.git
cd env-scanner
```

That's it—no `pip install` needed. The tool uses only the Python standard
library.

---

## Quick Start

Scan a project for hardcoded secrets (no files are modified):

```bash
python3 -m src.main examples/python-backend
```

Expected output:

```text
======================================================================
🛡️  ENV-GUARD: Cybersecurity Hardcoded Secret Scanner & Refactorer  🛡️
======================================================================

Mode: Scan-only
Target Directory: /path/to/examples/python-backend
Entropy Threshold: 4.5
Min String Length: 8
Scanning files recursively...

[⚠️  CRITICAL] Potential secret detected!
  File: config.py:13
  String: "jwt_signing_secret_key_1234567890_abcdefg_XYZ_!!!!"
  Entropy: 4.641
  Reason: Suspicious variable name
  Variable: JWT_SECRET

[⚠️  CRITICAL] Potential secret detected!
  File: config.py:16
  String: "postgresql://db_admin:admin_P@ssw0rd_987654321@prod-db.cluster.internal:5432/production"
  Entropy: 4.803
  Reason: Suspicious variable name
  Variable: DATABASE_URL

======================================================================
SCAN COMPLETED
======================================================================
Mode: Scan-only
Files Scanned with Findings: 1
Total Secret Candidates Flagged: 2
======================================================================
```

---

## Example Input and Output

Sample projects are in the `examples/` directory:

| Sample | Input | Secrets Found | Not Flagged |
|---|---|---|---|
| `examples/python-backend/` | Python config with JWT + DB URL | 2 | localhost URL, low-entropy greeting |
| `examples/js-ts-api-keys/` | JS + TS with AWS, Stripe, Google keys | 6 | Tailwind classes, greeting string |
| `examples/false-positives/` | TS with CSS, template literals, prose | 0 | Tailwind classes, CSS styles, `${}` interpolation, multi-line prompt, localhost URL, greeting |
| `examples/commented-secret/` | Python with secret in comment vs. real code | 2 | _(both are flagged — a secret in a comment is still committed to git)_ |

Expected outputs are documented in `examples/expected-output-python-backend.txt`,
`examples/expected-output-js-ts-api-keys.txt`, `examples/expected-output-false-positives.txt`,
and `examples/expected-output-commented-secret.txt`.

---

## CLI Options

```text
positional arguments:
  directory             Path to the source directory to scan

optional arguments:
  -h, --help            show this help message and exit
  -r, --refactor        Enable interactive refactor mode (default: scan-only)
  -t THRESHOLD, --threshold THRESHOLD
                        Shannon Entropy threshold (default: 4.5)
  -l MIN_LEN, --min-len MIN_LEN
                        Minimum length of string literals to analyze (default: 8)
  -e ENV, --env ENV     Target .env file path (default: <target_dir>/.env,
                        only used with --refactor)
  -d, --duplicate       Create a copy of the source directory (named
                        <dir>_env_guard_fixed) and operate on the copy.
                        Only meaningful with --refactor.
```

### Refactor Mode Example

```bash
python3 -m src.main my-project -r -d
```

This creates a copy of `my-project`, scans it, and for each finding prompts:

```text
Is this a secret credential? (y/n) [suggested: JWT_SECRET]:
```

If you confirm, the tool:
1. Appends `JWT_SECRET="..."` to `.env`.
2. Rewrites the source file: `JWT_SECRET = os.environ.get('JWT_SECRET')` (Python) or `const JWT_SECRET = process.env.JWT_SECRET;` (JS/TS).
3. Adds `import os` to Python files if not already present.

---

## Running Tests

```bash
python3 -m unittest tests.test_env_guard tests.test_real_mistakes -v
```

---

## Known Limitations

- **Language support for refactoring**: Python (`.py`), JavaScript (`.js`,
  `.jsx`), and TypeScript (`.ts`, `.tsx`). Scanning works on any text file;
  refactoring is language-specific.
- **Entropy is imperfect**: some non-secret strings with high character
  diversity may still be flagged. The false-positive filters catch common
  cases (CSS, Tailwind, template literals, prose, localhost URLs) but cannot
  cover every possible string.
- **Variable-name detection is keyword-based**: a variable like `secret_count`
  would be flagged because it contains `secret`. This is intentional—when in
  doubt, the tool errs on the side of reporting.
- **No `.env` file scanning**: `.env` files are deliberately skipped to avoid
  exposing real secrets during a scan.
- **Single-line secrets only**: multi-line strings (triple-quoted blocks,
  template literals with newlines) are filtered out by the entropy detector
  since they are almost always prose or embedded code, not single secrets.
  The variable-name and value-pattern detectors still run on all strings.

---

## Safety and Ethical Use

env-guard is a **defensive** tool. It reads files locally and reports findings.
It does not:

- transmit data over the network,
- attack systems or bypass access controls,
- collect or exfiltrate secrets,
- modify files unless explicitly instructed with `--refactor`.

Use it on your own codebases or codebases you are authorized to audit. The
sample projects in `examples/` and `tests/` contain only synthetic,
fake credentials designed for testing.

---

## License

MIT License — see [LICENSE](LICENSE).
