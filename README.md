# secret-scanner-cli

Local, offline secret scanning from the command line or a GitHub Action:
no IDE required. Detects 22 credential formats by their exact shape
(AWS, GitHub classic and fine-grained, GitLab, Slack tokens and webhooks,
Stripe, OpenAI, Anthropic, Hugging Face, Groq, Perplexity, Google, npm,
PyPI, SendGrid, Shopify, DigitalOcean, Databricks, HashiCorp Vault, JWTs
and PEM private keys), plus a name + Shannon-entropy check for a real
credential assigned to a credential-named key.

The name + entropy check is the strict one: the key's last word has to
be the credential noun (`api_token`, `DB_PASSWORD`; not `token_url` or
`secretName`), and references (`${VAR}`, `%VAR%`, `{{ secrets.X }}`),
paths, URLs without credentials, sentences and slugs are not reported.
In template and generated files (`*.example`, `*.sample`, lockfiles) only
the exact formats are checked. On four of my own repositories it cut the
name + entropy findings from 75 to 0, 3 to 1, and 227 to 147 (the rest
are cryptography test vectors in a vendored Go toolchain), while the
exact-format findings stayed the same.

**Status: v0.1, early.** Built as a companion channel to Gap Hunter
Labs' [api-security-companion](https://github.com/GapHunterLabs/api-security-companion)
IntelliJ plugin: its detection rules
([`SecretDetector.kt`](src/main/kotlin/dev/gaphunter/scannercli/SecretDetector.kt)
is a manual, deliberate port, not a shared module; see the file header
for why), packaged for teams that don't use a JetBrains IDE, or want the
check in CI rather than (or in addition to) the editor. This copy differs
from the plugin's on purpose in one place: a JWT has to start where the
previous character isn't a base64url character, which keeps a long
`-eyJ-eyJ...` line linear.

## Why a manual port instead of one shared module?

This project and the IntelliJ plugin build independently: one is a
plain JVM app, the other depends on the IntelliJ Platform Gradle
plugin. Sharing `SecretDetector.kt` as a real Gradle module was possible
but not done for v0.1; keeping two copies in sync by hand is a known,
deliberate trade-off, not an oversight. If you change the detection
rules in one place, mirror the change in the other.

## Install / build

Requires JDK 21.

```bash
git clone https://github.com/GapHunterLabs/secret-scanner-cli.git
cd secret-scanner-cli
./gradlew shadowJar
java -jar build/libs/secret-scanner-cli-0.1.0.jar --help
```

## Usage

```bash
java -jar secret-scanner-cli-0.1.0.jar [path] [options]

  path              Directory or single file to scan (default: current directory)
  --format <fmt>    Output format: text (default) or sarif
  --out <file>      Write output to a file instead of stdout
  --no-fail         Always exit 0, even if findings are reported
  --banner          Always print the startup banner (even piped or sarif)
  --no-banner       Never print the startup banner
  --version         Print version and exit
  -h, --help        Print this help and exit

The startup banner shows by default only in an interactive terminal with
--format text and no --out: never when the output is piped, redirected, or
meant for a script or CI to parse (so a GitHub Action run never sees it).

Exit codes: 0 = no findings (or --no-fail), 1 = findings reported, 2 = usage/path error.
```

Example:

```bash
$ java -jar secret-scanner-cli-0.1.0.jar ./my-repo
my-repo/.env:1:19: [AWS_ACCESS_KEY] Looks like an AWS access key ID (AKIAIOSF...)

secret-scanner-cli: 1 finding(s) in ./my-repo
```

## GitHub Action

This repository is itself a composite GitHub Action. Point a workflow
at it directly:

```yaml
name: Secret scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # only needed if upload-sarif stays 'true'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: GapHunterLabs/secret-scanner-cli@v0.1.0
        with:
          path: '.'
          fail-on-find: 'true'
          upload-sarif: 'true'
```

Inputs: `path` (default `.`), `fail-on-find` (default `true`),
`upload-sarif` (default `true`, uploads to GitHub Code Scanning via
`github/codeql-action/upload-sarif`, which needs `security-events: write`
and Code Scanning available on the repo; public repos have this free,
private repos need GitHub Advanced Security). Outputs: `finding-count`,
`sarif-file`.

File paths in the SARIF report are relative to the directory the job runs
in (the repository root on GitHub Actions), so `path: src` reports
`src/Config.kt` and Code Scanning finds the file. A path outside that
directory is reported relative to the scanned folder; no absolute path is
ever written into the report.

**Known limitation, honestly noted:** the action builds this project
from source on every run (see [`action.yml`](action.yml)) rather than
downloading a pre-built release jar: simple for v0.1, but it costs
every consumer a Gradle build. Publishing tagged release jars and
switching the action to download one is a real follow-up, not done
yet. The action runs on every push to `main` in this repository's own
CI (the `self-scan` job scans `src/main` with `uses: ./`), so the build
and scan steps have run in real GitHub Actions workflows. That job uses
`upload-sarif: 'false'` and finds nothing, so two paths have **not yet
run live**: the SARIF upload to Code Scanning and a run that fails on
findings. Treat those two as unverified until they have.

How I test the tool, including the negative and stress suites, is in
[docs/TESTING.md](docs/TESTING.md).

## What this tool is not

It's a coarse, regex-based scanner, not a real per-language parser.
Known blind spots: multi-line string values aren't matched, and a
value split across string concatenation (`"AKIA" + "IOSF..."`) won't
be caught either (the same is true of the IntelliJ plugin's
PSI-based version, for what it's worth: concatenation defeats both).
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
