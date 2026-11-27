# Changelog

## 0.3.0

### Fixed

- **Key names with suffixes.** `API_KEY_1`, `DB_PASSWORD_PROD`, `AUTH_TOKEN_V2` and
  `apiKeyProd` were never checked, because the credential noun had to be the last
  word. Environment and numbering suffixes (`_1`, `_PROD`, `_DEV`, `_STAGING`,
  `_PRIMARY`, `_SECONDARY`, `V2`...) are now dropped first, and every naming
  convention (camelCase, PascalCase, kebab-case, snake_case, dotted) is split into
  words the same way.
- **A UTF-8 byte-order mark hid the first line.** `API_TOKEN=...` on line 1 of a
  `.env` saved with a BOM was not reported. The mark is now honored and removed.
- **UTF-16 files** (with or without a byte-order mark) are now read; they were a
  documented blind spot.
- **Column numbers.** An exact format in the middle of a line was always reported at
  column 1; it now gets its real column and an end column. A value is located at the
  assignment that matched, not at its first appearance on the line. SARIF declares
  `columnKind: utf16CodeUnits`.
- **`--out` problems are caught before the scan.** A Windows reserved device name
  (`con.sarif`, `nul.json`) used to send the report to the console device and exit 1
  with no file; an invalid file name was only found after the whole scan. Both, plus
  a read-only file or directory, are now exit 2 before anything is read, with the
  path and the cause.
- **Flags.** A single-value flag given twice (`--format text --format sarif`) used
  to keep the last one silently; it is now an error, like every new conflicting pair.
- **Placeholders.** AWS's documentation example key (ending in `EXAMPLE`) and a token
  body made of redaction characters (`ghp_XXXX...`, `sk-proj-****...`) are no longer
  reported; one real character in ten is enough to report it again.
- **Console output.** Control characters, ANSI escape sequences and bidirectional
  overrides in file names, links or descriptions are printed as visible `\uXXXX`.

### Changed

- **Binary content behind a text extension** (a NUL byte in the first 8 KB) is skipped
  and listed instead of being read as text.
- **Report paths** in text output are relative to the working directory when the
  scanned folder is inside it (`src/Config.kt` when scanning `src`), the same paths
  SARIF already used.
- **Descriptions** no longer carry the first characters of a secret; every format
  shows a masked view instead (`abcd...wxyz`).
- **Skipped links** are reported in one line per run (the first five and a count),
  not one line each.

### Added

- `--format json`, and SARIF rule metadata (`security-severity`, default level),
  per-finding levels and stable `partialFingerprints`.
- Severity per rule and `--fail-on all|medium|high|none`.
- `--quiet`, `--verbose`, and a summary: files scanned and skipped by reason,
  findings by rule and severity, duration.
- `.secret-scanner.json` configuration, `--config`, `--no-config`.
- `.scannerignore` and `--exclude` (a subset of gitignore patterns).
- Several paths in one run, directories and files mixed; a file reached twice is
  read once.
- `--max-file-size` (default 25 MB) and `--max-findings`.
- `--reveal <N>` to show more of each secret on purpose.
- `--dry-run`.
- `--self-sha256` and `--expect-sha256`; the jar's SHA-256 in JSON and SARIF.
- A `test-or-example` tag for findings under test, fixture and example paths.
- Ten exact formats: Atlassian API token, Doppler, age secret key, Linear, Postman,
  Grafana service account, Square access token, PuTTY private key, Azure Storage
  account key, bcrypt hash; the private key rule now covers every PEM and PGP header.
- GitHub Action: `fail-on`, `config` and `max-file-size` inputs; third-party actions
  pinned by commit SHA; workflow commands switched off around the tool's output.
  The repository's CI declares `permissions: contents: read`.

## 0.2.0

- Links that lead outside the scanned folder are not followed by default
  (`--follow-external-links` restores 0.1.0's behavior).
- The plugin's 22 exact formats and its strict name + entropy check; ReDoS fixes,
  SARIF paths relative to the repository, and CLI edge cases.

## 0.1.0

- First release.
