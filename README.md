# secret-scanner-cli

Local, offline secret scanning from the command line or a GitHub Action:
no IDE required. Detects 32 credential formats by their exact shape, plus
a name + Shannon-entropy check for a real credential assigned to a
credential-named key. Text, JSON and SARIF output; SARIF goes straight
into GitHub Code Scanning.

The name + entropy check is the strict one: the key's last word has to
be the credential noun (`api_token`, `DB_PASSWORD`; not `token_url` or
`secretName`), whatever the naming convention, and with environment or
numbering suffixes removed first (`API_KEY_1`, `DB_PASSWORD_PROD`,
`apiKeyV2`). References (`${VAR}`, `%VAR%`, `{{ secrets.X }}`), paths,
URLs without credentials, sentences, slugs and placeholders are not
reported. In template and generated files (`*.example`, `*.sample`,
lockfiles) only the exact formats are checked. On four of my own
repositories it cut the name + entropy findings from 75 to 0, 3 to 1,
and 227 to 147 (the rest are cryptography test vectors in a vendored Go
toolchain), while the exact-format findings stayed the same.

**Status: v0.3.1.** Built as a companion channel to Gap Hunter Labs'
[api-security-companion](https://github.com/GapHunterLabs/api-security-companion)
IntelliJ plugin: its detection rules
([`SecretDetector.kt`](src/main/kotlin/dev/gaphunter/scannercli/SecretDetector.kt)
is a manual, deliberate port, not a shared module; see the file header
for where this copy differs), packaged for teams that don't use a
JetBrains IDE, or want the check in CI. What changed in each version is in
[CHANGELOG.md](CHANGELOG.md).

## Install / build

Requires JDK 21.

```bash
git clone https://github.com/GapHunterLabs/secret-scanner-cli.git
cd secret-scanner-cli
./gradlew shadowJar
java -jar build/libs/secret-scanner-cli-0.3.1.jar --help
```

## Usage

```text
java -jar secret-scanner-cli-0.3.1.jar [path...] [options]

  path...             Directories and/or files to scan (default: current directory)
  --format <fmt>      Output format: text (default), sarif or json
  --out <file>        Write the report to a file instead of stdout
  --fail-on <level>   Exit 1 only for findings at this severity or above:
                      all (default), medium, high, or none
  --no-fail           Always exit 0 (same as --fail-on none)
  --quiet             Only findings and errors: no banner, summary or notices
  --verbose           List every skipped file and link, and the run's numbers
  --config <file>     Read this JSON configuration instead of ./.secret-scanner.json
  --no-config         Ignore ./.secret-scanner.json and ./.scannerignore
  --exclude <glob>    Leave out matching paths (repeatable; gitignore-style)
  --max-file-size <MB>
                      Skip larger files (default 25, 0 = no limit)
  --max-findings <N>  List at most N findings (the exit code still counts all)
  --reveal <N>        Show the first N characters of each secret (1-64);
                      by default only a masked view like abcd...wxyz
  --dry-run           Check flags, configuration and paths, count the files
                      that would be read, and exit without reading them
  --follow-external-links
                      Also scan through links (symlinks, junctions) that lead
                      outside the scanned folder; not followed by default
  --self-sha256       Print the SHA-256 of this jar and exit
  --expect-sha256 <hex>
                      Refuse to scan (exit 2) unless this jar has that SHA-256
  --banner / --no-banner
  --version, -h / --help

Exit codes: 0 = no findings at the --fail-on level, 1 = findings at that level,
2 = usage, configuration or path error (always before any file is read).
```

Example:

```text
$ java -jar secret-scanner-cli-0.3.1.jar my-repo
my-repo/.env:1:19: [AWS_ACCESS_KEY] [high] Looks like an AWS access key ID (AKIA...WZ8K)
my-repo/tests/fixtures/app.yaml:4:13: [GENERIC_HIGH_ENTROPY] [medium] Assigned to 'API_KEY_PROD' and looks like a real credential, not a placeholder or a reference (q7Lm...3Nb6) [test-or-example]

secret-scanner-cli: 2 finding(s) in my-repo
secret-scanner-cli: scanned 214 file(s), 1.8 MB, in 0.41 s; skipped 1 (1 too large)
secret-scanner-cli: by rule: AWS_ACCESS_KEY 1, GENERIC_HIGH_ENTROPY 1
secret-scanner-cli: by severity: 1 high, 1 medium
```

A file path, a link or a description is printed with every control
character (ANSI escape sequences included) and every bidirectional override
shown as a visible `\uXXXX`, so a crafted file name cannot rewrite your
terminal or a CI log.

## Output formats

| Format | Where it goes | What it carries | Use it for |
| --- | --- | --- | --- |
| `text` | stdout (or `--out`) | One line per finding (`path:line:column: [RULE] [severity] description (masked)`), then the summary | People, local runs |
| `sarif` | stdout (or `--out`); the summary goes to stderr | SARIF 2.1.0: rule metadata with `security-severity`, `error`/`warning` level per finding, start and end column (`columnKind: utf16CodeUnits`), a stable `partialFingerprints` entry, and the run's numbers in `runs[0].properties` | GitHub Code Scanning and other security dashboards |
| `json` | stdout (or `--out`); the summary goes to stderr | `tool` (name, version, jar SHA-256), `summary` (counts by rule and severity, files scanned and skipped, duration) and `findings` (path, line, columns, rule, severity, masked value, fingerprint, tags) | Scripts and other automation |

No format ever contains a complete secret. By default each secret is shown
as its first 4 and last 4 characters (`abcd...wxyz`) when it has 16 or more,
its first 2 when it has 8 to 15, and nothing below that. `--reveal <N>` shows
the first N characters (at most 64) when you need to tell two keys apart.

The SARIF fingerprint is built from the rule, the path, a SHA-256 of the
secret and which occurrence of that secret in that file it is. It has no line
number, so a finding that moves down a few lines is the same alert on the next
run, and the secret itself never goes into it.

## What it detects

| Severity | Rules |
| --- | --- |
| high | AWS access key, GitHub token (classic and fine-grained), GitLab, Slack token and webhook, Stripe, OpenAI, Anthropic, Hugging Face, Groq, Perplexity, npm, PyPI, SendGrid, Shopify, DigitalOcean, Databricks, HashiCorp Vault, JWT, private key headers (PEM and PGP), PuTTY private key, age secret key, Azure Storage account key in a connection string, Atlassian, Doppler, Linear, Postman, Grafana service account, Square access token |
| medium | Google API key (it may be a Firebase web key, public by design), bcrypt password hash, and the name + entropy check (`GENERIC_HIGH_ENTROPY`) |

Several of the 0.3.0 shapes follow the public rule set of
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT), where I left out the
ones that need a nearby keyword to be precise. Findings under a test or example
path (`test/`, `fixtures/`, `examples/`, `*Test.kt`, `*.spec.ts`, `test_*.py`...)
are tagged `test-or-example`; their severity does not change, because a real
token committed in `tests/` is still a leak.

### How files are read

- Only files with a source or configuration extension are read; build output,
  dependency folders and VCS metadata are skipped.
- A file larger than `--max-file-size` (25 MB by default) is skipped and listed.
- A NUL byte in the first 8 KB means binary content behind a text extension: the
  file is skipped and listed (the same rule git uses).
- A UTF-8 or UTF-16 byte-order mark is honored and is not part of line 1. UTF-16
  without a mark is recognized by its NUL pattern. Latin-1 and Windows-1252 files
  are read with one replacement character per invalid byte, so columns stay one
  per byte, as those editors show them.
- Line and column numbers are exact for exact formats anywhere on a line; a column
  counts UTF-16 code units, so a tab counts as one.

## Configuration and exclusions

An optional `.secret-scanner.json` in the directory the scan runs from (or the
file given with `--config`) holds the project's settings, so CI and local runs
use the same ones:

```json
{
  "exclude": ["tests/fixtures/", "*.snap.json"],
  "disableRules": ["GOOGLE_API_KEY"],
  "failOn": "high",
  "maxFileSizeMb": 10,
  "maxFindings": 200,
  "followExternalLinks": false
}
```

Every key is optional. An unknown key, a value of the wrong type or an unknown
rule id is an error that names it (exit 2), never a setting quietly ignored.
Command-line flags win over the file. The file is JSON only: YAML would need a
parser dependency, and this tool ships as one jar with no dependencies.

Exclusion patterns come from `.scannerignore` (next to the configuration file),
the configuration's `exclude` list and `--exclude`. They follow a subset of
`.gitignore`: `*`, `?` and `**`; a leading or middle `/` anchors the pattern to
the top, a trailing `/` matches directories only, `#` starts a comment. They are
matched against the paths the report shows. Negation (`!pattern`) is rejected
with an error instead of being ignored. A file you name on the command line is
always scanned.

`--dry-run` checks all of this (flags, configuration, patterns, paths and
`--out`), counts the files a scan would read, and exits without reading them.

### Reducing false positives without losing coverage

1. **Start with `--fail-on high`.** Exact formats are almost never wrong; the
   name + entropy rule is the one that needs tuning. Fail the build on high
   findings first, read the medium ones in the report, then move to `all`.
2. **Exclude by path, not by rule.** `tests/fixtures/` in `.scannerignore` keeps
   every rule active everywhere else. Disabling a rule turns it off for the
   whole repository.
3. **Use placeholders that look like placeholders.** `changeme`, `<YOUR_API_KEY>`,
   `${API_KEY}`, `REPLACE_ME` or a token body of `X` characters are not reported.
   AWS's documentation example key (ending in `EXAMPLE`) is not reported either.
4. **Keep templates as templates.** In `*.example`, `*.sample` and `*.template`
   files only exact formats are checked.
5. **Read the `test-or-example` tag.** It tells you where to look first; it does
   not hide anything.

## GitHub Action

This repository is itself a composite GitHub Action.

### Report to Code Scanning, fail on any finding

```yaml
name: Secret scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # only needed while upload-sarif stays 'true'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4.4.0
      - uses: GapHunterLabs/secret-scanner-cli@v0.3.1
        with:
          path: '.'
```

### Gradual adoption: fail only on exact formats, report the rest

```yaml
      - uses: GapHunterLabs/secret-scanner-cli@v0.3.1
        with:
          fail-on: 'high'
          config: '.secret-scanner.json'
```

### Report only, no Code Scanning (private repository without Advanced Security)

```yaml
permissions:
  contents: read
# ...
      - uses: GapHunterLabs/secret-scanner-cli@v0.3.1
        with:
          fail-on-find: 'false'
          upload-sarif: 'false'
```

Inputs: `path` (default `.`), `fail-on-find` (default `true`), `fail-on`
(`all`, `medium`, `high` or `none`; default `all`), `config` (default: the
repository's `.secret-scanner.json` when present), `max-file-size` (megabytes;
default 25), `upload-sarif` (default `true`, via
`github/codeql-action/upload-sarif`, which needs `security-events: write` and
Code Scanning on the repo; public repos have it free, private repos need GitHub
Advanced Security). Outputs: `finding-count`, `sarif-file`.

How the action is hardened:

- Every input reaches the script through an environment variable, never through
  `${{ }}` inside the script text, and each one is checked before use, so a path
  like `repo$(touch x)` is just a path that does not exist.
- Third-party actions are pinned to a full commit SHA, not a tag.
- Workflow commands are switched off (`::stop-commands::`) around everything the
  tool prints, so a committed file named `::error::...` cannot inject one, and
  they come back on every exit path.
- Paths in the SARIF report are relative to the repository root (`path: src`
  reports `src/Config.kt`); no absolute path is ever written.

To check that the jar you run is the one you expect, pin its SHA-256 in the
workflow: `java -jar secret-scanner-cli-0.3.1.jar --expect-sha256 <hex> .`
refuses to scan (exit 2) on any other artifact. `--self-sha256` prints it, and
the JSON and SARIF reports record it.

**How the action gets the tool:** used at a release tag (`@v0.3.1` or later),
it downloads the jar attached to that GitHub Release and checks it against the
SHA-256 stored in this repository (`checksums/`); a file that does not match stops
the step, with no fallback. Used at a branch, a commit SHA or an older tag, or when
the download fails, it builds from source with Gradle. The `self-scan` job in this
repository's CI runs the action on every push to `main`; it finds nothing and does
not upload, so the SARIF upload and a run that fails on findings have not run live yet.

How I test the tool, including the negative, mutation and stress checks, is in
[docs/TESTING.md](docs/TESTING.md).

## Links that leave the scanned folder

A symlink or Windows junction whose real path is outside the folder you scan is
not followed: a link committed in a pull request (to `/etc`, or to a home
directory) would otherwise make a CI scan read files that are not part of the
repository. Links left out are listed on stderr by their path inside the tree,
never by their target, in one line with the first five and a count of the rest
(`--verbose` lists all of them). `--follow-external-links` follows them.

## What this tool is not

It's a coarse, regex-based scanner, not a real per-language parser.
Known blind spots: multi-line string values aren't matched, and a
value split across string concatenation (`"AKIA" + "IOSF..."`) won't
be caught either (the same is true of the IntelliJ plugin's
PSI-based version: concatenation defeats both).
It's meant to catch the common, careless case cheaply, not to replace
a dedicated secret-scanning product for anything security-critical.

## Privacy

See [PRIVACY.md](PRIVACY.md). Short version: this tool makes zero
network calls, reads only the files you point it at, and sends
nothing anywhere.

## Support this project

If this tool saved you time, a star on GitHub helps other developers find it: https://github.com/GapHunterLabs/secret-scanner-cli

If you want to help keep it free and maintained, you can buy me a coffee:

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=flat&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/gaphunterl1)

## License

Apache License 2.0. See [LICENSE](LICENSE).
