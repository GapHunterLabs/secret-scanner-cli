# Testing secret-scanner-cli

I keep three kinds of tests in `src/test/kotlin`. The normal and negative
suites run on every `./gradlew test` and in CI. The stress suite is heavy, so
it runs only when I ask for it.

## Normal and negative suites (every build)

```bash
./gradlew test
```

| Test class | What it covers |
| --- | --- |
| `ScannerTest` | The original happy paths: one finding per detector family, skipped directories and extensions, line numbers. |
| `OutputFormatTest` | Text and SARIF rendering of a single finding. |
| `BannerTest` | When the startup banner shows and when it stays hidden. |
| `DetectorBoundaryTest` | Every detector at its boundary: the shortest value that matches, one character shorter (no match), a wrong prefix, wrong case, a value inside a comment, values masked with `*` (ignored) and with `X` (still reported, a known false positive). Proves that no output format, text or SARIF, ever contains a complete secret or more than its first 11 characters. CRLF, LF and CR line endings give the same lines and columns. |
| `ScannerNegativeTest` | Empty directory, empty file, a single file as the root (scanned whatever its extension, reported by its own name), a root named like a skipped directory (`build`, `vendor`, ...), binary bytes and malformed UTF-8 in a text file, UTF-16 (a known blind spot), a locked file on Windows (skipped), directory link loops and two links to one directory (each real directory is entered once), and the ReDoS regressions. |
| `SarifNegativeTest` | SARIF stays valid JSON with every control character in a file name or message, file names become valid URI references (spaces, `#`, `%`, `?`, `:`, non-ASCII), every rule id has its own description, and `--out` problems are found before the scan. |
| `CliNegativeTest` | The whole command line in-process: every format with every exit code (0, 1, 2), `--no-fail`, unknown flags, a flag missing its value, an invalid `--format`, `--out` followed by a flag, two paths, `--banner` with `--no-banner`, `--out` to a missing directory, to a directory and to a read-only file, `--out` inside the scanned tree (the report never produces findings of its own), `--version` and `--help`. One test starts a real child JVM to check the process exit status. |
| `DemoFixtureTest` | End to end on the small demo project in `src/test/resources/demo-fixture`: exactly seven expected findings, in both formats, with no complete secret in the output. |

### Test secrets

No complete secret-shaped value is committed. The tests build every fake token
at runtime from pieces (`Fake` in `TestSupport.kt`), and the demo fixture holds
`{{NAME}}` markers that the test fills in a temporary directory. All values are
fake: the AWS key is AWS's documented example key, the Stripe key is the one in
Stripe's public docs, the GitHub tokens fail their checksum, and the JWT has a
fake signature.

## Stress suite (on demand)

```bash
./gradlew test -Pstress
```

This runs `StressTest` too and appends one line per case (wall time and peak
heap) to `build/reports/stress/stress-results.txt`. Without `-Pstress` every
stress test is reported as skipped. The build passes the setting to the tests
on every run, and a test fails if it ever stops doing so: before that, the
flag silently did nothing and the stress tests were skipped in a green run. The test JVM has a fixed 512 MB heap, so the numbers
also show what fits in it.

| Case | What it proves |
| --- | --- |
| 50 MB file | A large file is streamed line by line and still finds the one secret at its end. |
| Single 5 MB line, one run of key characters | The quoted-assignment rule stays linear on its worst input. |
| Single 5 MB line of `-eyJ` | The JWT rule stays linear on its worst input. |
| Every pattern at 1 MB | An adversarial 1 MB line for each regex in the detector and the scanner, through the file scanner and through the detector alone. |
| 10,000 small files | Directory walking cost. |
| 300 nested directories | Deep trees, including paths longer than 260 characters on Windows. |
| 100,000 findings | Scanning, text rendering, SARIF rendering and parsing the SARIF back. |

The time budgets are loose on purpose: they catch a quadratic regression or an
out-of-memory error, not a small slowdown.

## Checks I run outside Gradle

- **SARIF schema.** I validate the SARIF the tool writes against the official
  SARIF 2.1.0 JSON schema from OASIS with a JSON Schema validator, plus a
  check that every `artifactLocation.uri` is a valid URI reference. The schema
  is downloaded at check time and not stored in this repository.
- **The action's scan step.** I run the `Run scan` step of `action.yml` with
  bash on a local workspace, expanding `${{ }}` the way the runner does, with
  a temporary `GITHUB_OUTPUT`. This covers the exit status for each
  `fail-on-find` value, the `finding-count` output and paths with spaces or
  shell syntax. The build step, `actions/setup-java` and the SARIF upload only
  run on GitHub.
- **The shadow jar.** `./gradlew shadowJar` and then
  `java -jar build/libs/secret-scanner-cli-0.2.0.jar <dir>` on a filled copy of
  the demo fixture, in both formats.
