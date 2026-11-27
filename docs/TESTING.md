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
| `DetectorBoundaryTest` | Every detector at its boundary: the shortest value that matches, one character shorter (no match), a wrong prefix, wrong case, a value inside a comment, values masked with `*` or `X` (ignored since 0.3.0; one real character in ten is reported again). Proves that no output format ever contains a complete secret, and that descriptions carry no part of it. CRLF, LF and CR line endings give the same lines and columns. |
| `ScannerNegativeTest` | Empty directory, empty file, a single file as the root (scanned whatever its extension, reported by its own name), a root named like a skipped directory (`build`, `vendor`, ...), binary content behind a text extension (skipped and listed), malformed UTF-8, UTF-16 without a byte-order mark (read since 0.3.0), a locked file on Windows (skipped), directory link loops and two links to one directory (each real directory is entered once), and the ReDoS regressions. |
| `SarifNegativeTest` | SARIF stays valid JSON with every control character in a file name or message, file names become valid URI references (spaces, `#`, `%`, `?`, `:`, non-ASCII), every rule id has its own description, and `--out` problems are found before the scan. |
| `CliNegativeTest` | The whole command line in-process: every format with every exit code (0, 1, 2), `--no-fail`, unknown flags, a flag missing its value, an invalid `--format`, a flag given twice, every conflicting pair, out-of-range numbers, `--out` followed by a flag, `--banner` with `--no-banner`, `--out` to a missing directory, to a directory and to a read-only file, `--out` inside the scanned tree (the report never produces findings of its own), `--version` and `--help`. One test starts a real child JVM to check the process exit status. |
| `KeyNameTest` | Key names in every convention split into the same words; environment and numbering suffixes (`API_KEY_1`, `DB_PASSWORD_PROD`, `AUTH_TOKEN_V2`, `apiKeyProd`) are dropped before the noun is checked; keys about a credential (`token_url`, `TOKEN_URL_PROD`, `cache_key`) stay unreported; a bare suffix is never stripped to nothing. |
| `FormatsAndReadingTest` | The ten 0.3.0 formats at their shortest length and one character less, PEM and PGP headers, severity per rule, disabled rules, placeholders and empty URL parameters, a UTF-8 byte-order mark on line 1, UTF-16 with a mark in both byte orders, Latin-1 and Windows-1252 columns, a truncated UTF-8 file, exact columns for a format in the middle of a line, after an emoji or a tab, on a 200,000-character line and when the value appears earlier on the line, the size limit (below, at and above it, and 0), a NUL after the first 8 KB, empty files, and the test-or-example tag. |
| `CliFeaturesTest` | JSON output, empty and clean folders in every format with no warnings, `--fail-on` at every level, the summary and `--quiet`, consolidated notices and `--verbose`, the configuration file (and every way it can be wrong), `.scannerignore` and `--exclude`, several paths and a file reached twice, clean SARIF paths with `./`, `\`, `..` and a single file, two roots outside the working directory, `--max-findings`, the mask and `--reveal`, `--dry-run`, self-verification, `--out` checks (reserved names, invalid characters, the write probe), SARIF metadata and fingerprints that survive a line move, console escaping, and static checks of `action.yml` and the CI workflow (no `${{ }}` inside a script, every third-party action pinned by SHA, least-privilege permissions, `::stop-commands::`). |
| `DemoFixtureTest` | End to end on the small demo project in `src/test/resources/demo-fixture`: exactly seven expected findings, in both formats, with no complete secret in the output. |

### Test secrets

No complete secret-shaped value is committed. The tests build every fake token
at runtime from pieces (`Fake` in `TestSupport.kt`), and the demo fixture holds
`{{NAME}}` markers that the test fills in a temporary directory. All values are
fake: the AWS key has the right shape but is made up (AWS's documented example key is a placeholder since 0.3.0), the Stripe key is the one in
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
  bash on a local workspace, passing the inputs as environment variables the
  way the runner does, with a temporary `GITHUB_OUTPUT`. This covers the exit
  status for each `fail-on-find` and `fail-on` value, invalid values, the
  `finding-count` output, and hostile inputs (`$(...)`, quotes and `;` in the
  path, the configuration and the size limit), none of which runs as a command.
  It also checks that workflow commands come back on after an early exit. The build step, `actions/setup-java` and the SARIF upload only
  run on GitHub.
- **The shadow jar.** `./gradlew shadowJar` and then
  `java -jar build/libs/secret-scanner-cli-0.3.1.jar <dir>` on a filled copy of
  the demo fixture, in both formats.
- **Mutation check.** For each fix in 0.3.0 (suffixes, the byte-order mark,
  redaction placeholders, the AWS example key, console escaping, the column of a
  format, Windows reserved names, the line-free fingerprint, consolidated notices,
  the size limit) I undo the fix and confirm that at least one test fails.

