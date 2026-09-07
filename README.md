# secret-scanner-cli

Local, offline secret scanning from the command line or a GitHub Action
— no IDE required. Detects hardcoded AWS/GitHub/Slack/Stripe keys, JWTs,
and PEM private keys by format, plus a variable-name + Shannon-entropy
heuristic for everything else that looks like a real credential
assigned to a suspiciously-named field.

**Status: v0.1, early.** Built as a companion channel to Gap Hunter
Labs' [api-security-companion](https://github.com/GapHunterLabs/api-security-companion)
IntelliJ plugin — same detection rules
([`SecretDetector.kt`](src/main/kotlin/dev/gaphunter/scannercli/SecretDetector.kt)
is a manual, deliberate port, not a shared module — see the file header
for why), packaged for teams that don't use a JetBrains IDE, or want the
check in CI rather than (or in addition to) the editor.

## Why a manual port instead of one shared module?

This project and the IntelliJ plugin build independently — one is a
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

  path              Directory to scan (default: current directory)
  --format <fmt>    Output format: text (default) or sarif
  --out <file>      Write output to a file instead of stdout
  --no-fail         Always exit 0, even if findings are reported
  --version         Print version and exit
  -h, --help        Print this help and exit

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
`github/codeql-action/upload-sarif` — needs `security-events: write`
and Code Scanning available on the repo; public repos have this free,
private repos need GitHub Advanced Security). Outputs: `finding-count`,
`sarif-file`.

**Known limitation, honestly noted:** the action builds this project
from source on every run (see [`action.yml`](action.yml)) rather than
downloading a pre-built release jar — simple for v0.1, but it costs
every consumer a Gradle build. Publishing tagged release jars and
switching the action to download one is a real follow-up, not done
yet. The action itself has been reviewed against GitHub Actions'
documented composite-action behavior but has **not yet been run in a
live GitHub Actions workflow** — treat it as unverified in that
specific environment until it has.

## What this tool is not

It's a coarse, regex-based scanner — not a real per-language parser.
Known blind spots: multi-line string values aren't matched, and a
value split across string concatenation (`"AKIA" + "IOSF..."`) won't
be caught either (the same is true of the IntelliJ plugin's
PSI-based version, for what it's worth — concatenation defeats both).
It's meant to catch the common, careless case cheaply, not to replace
a dedicated secret-scanning product for anything security-critical.

## Privacy

See [PRIVACY.md](PRIVACY.md) — short version: this tool makes zero
network calls, reads only the files you point it at, and sends
nothing anywhere.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
