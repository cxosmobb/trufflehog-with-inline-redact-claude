# Secret redaction

This fork of [trufflehog](https://github.com/trufflesecurity/trufflehog) adds a
`redact` command that overwrites the secrets trufflehog finds with `REDACTED`,
in place. It is meant for a pre-scan stage: source code imported from
elsewhere is redacted before it is handed to a scanner (or anything else) that
must not see credentials.

```bash
trufflehog redact ./src              # report what would be redacted
trufflehog redact ./src --in-place   # redact
```

Everything else trufflehog does is unchanged. The fork follows upstream's
`main` automatically (see [Syncing with upstream](#syncing-with-upstream)).

On Windows, download `trufflehog_<version>_windows_amd64.zip` (or `arm64`)
from the [releases](https://github.com/cxosmobb/trufflehog-with-inline-redact-claude/releases), unpack it and run
`trufflehog.exe redact <path> --in-place`. No administrator rights are needed.
Elsewhere, build it with `go build -o trufflehog .`.

## Usage

```
trufflehog redact <path>... [--in-place] [--replacement=REDACTED] [--max-passes=5]
                            [--remove-unredactable] [--verify] [-i include-file] [-x exclude-file]
```

| Flag | Meaning |
|---|---|
| `--in-place` | Write the redacted content back. Without it, `redact` only reports. |
| `--replacement` | Text written over each secret (default `REDACTED`). |
| `--max-passes` | Redact-and-rescan passes before giving up (default 5, see below). |
| `--remove-unredactable` | Delete files whose secrets cannot be redacted in place, such as secrets in zip files. |
| `--verify` | Verify secrets with their providers first. Off by default: nothing is sent anywhere. |
| `-i`, `-x` | Include/exclude path regex files, as for `filesystem`. |

Global flags work as usual, e.g. `--json`, `--include-detectors`,
`--exclude-detectors`, `--results`, `--config` (custom detectors) and
`--concurrency`.

`redact` differs from `filesystem` in three defaults, all chosen so that
nothing leaks: it does not verify, it does not honor `trufflehog:ignore`
comments (the input is untrusted), and it also redacts results trufflehog
would drop as wordlist false positives. Pass `--results` to change the last.
Without `--verify` every secret is unverified, so `--results` must then
include `unverified` (and `--only-verified` needs `--verify`); otherwise
`redact` refuses to run rather than silently redacting nothing.

Output has one line per redacted region and never contains secret values,
so it is safe to keep in CI logs:

```
redacted      src/config.py:12  AWS
redacted      k8s/secret.yaml:6  PrivateKey [base64]
residual      creds/sa.json:3  GCP  (detector still matches the redacted structure; no secret material is left)
unredactable  dist/app.zip  SlackWebhook  (secret not found in the file's bytes)
```

With `--json` each line is a JSON object with `action`, `file`, `line`,
`detectors`, `encoding` and `bytes`. In plain output, file names and errors
that contain control characters are printed quoted, so a crafted file name
cannot forge or hide report lines.

Exit status with `--in-place`: `0` when everything was redacted, `1` when a
finding could not be redacted (the files that could be redacted still are).
The command fails closed: a secret it cannot find in the file's bytes is an
error, never silently skipped.

### In a pipeline

```bash
git clone --depth 1 "$REPO" src
rm -rf src/.git                       # history is not redacted, see Limitations
trufflehog redact src --in-place --json > redactions.jsonl
untrusted-scanner src
```

## What gets redacted

Only secret material is overwritten. The surrounding text, the quotes around
a secret and the identifiers detectors report alongside it stay as they are:

| Input | Output |
|---|---|
| `aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/...` | `aws_secret_access_key = REDACTED` (the access key ID line is kept) |
| `token: "ghp_R2d2C3po..."` | `token: "REDACTED"` |
| a PEM private key | header and footer kept, body replaced by `REDACTED` |
| a GCP service account JSON | only `private_key` is replaced |
| `dGVzdDpodW50ZXIy...` (base64 holding a secret) | base64 of the content with the secret replaced, so it still decodes |
| `amqps://app:s3cr3t@mq:5672/vhost` | `amqps://REDACTED@mq:5672/vhost`, see [widening](#rescanning-and-widening) |
| `Server=db;User Id=sa;Password=s3cr3t;` | `Server=db;User Id=sa;REDACTED;`, see [widening](#rescanning-and-widening) |

The rules, in order:

- **Which values are secret.** Detectors report a credential's parts in
  `SecretParts`. Parts that identify rather than authenticate (`username`,
  `host`, `url`, `access_key_id`, `client_id`, ... see `identifierParts` in
  `pkg/redact/targets.go`) are kept; every other part is redacted, including
  keys no one has classified yet. Detectors without `SecretParts` have `Raw`
  redacted. A JSON document is redacted field by field, and a base64
  `user:password` value also has its password redacted wherever it appears.
- **Where.** Every occurrence of a secret in the file is redacted, in the
  form trufflehog decoded it from: plain text, nested base64 (redacted inside
  and re-encoded), UTF-16, escape sequences (`\n`, `A`, `\x41`, `U+0041`,
  also multiply escaped), percent-encoding and HTML. Secrets too short or
  common to be told apart from other text (such as a password `admin1`) are
  only redacted next to the rest of their credential.
- **Containers.** A secret inside structure is narrowed to the secret: the
  password of a URI, the `Password=` / `AccountKey=` / `sig=` value of a
  connection or query string, the body of a PEM block.
- **Token boundaries.** When a detector's pattern stops short of the end of a
  token (some cap a secret's length), the rest of the token is redacted too,
  so no fragment of the secret remains.
- **Binary files** (anything with NUL bytes or invalid UTF-8, including
  uncompressed archives such as tar) keep their size: the replacement is
  padded with `*` or truncated to the length of the secret
  (`REDACTED*****...`), so offsets inside the file stay valid.

### Rescanning and widening

With `--in-place`, redacted files are scanned again, until a pass changes
nothing or `--max-passes` is reached. A final scan then checks that nothing is
left. Rescanning catches two things:

1. Secrets a detector only reports once another secret is gone, because some
   detectors report a limited number of candidates per chunk.
2. Detectors that still report a credential whose secret is now `REDACTED`.
   For example, Postgres flags `user:REDACTED@host`, and JDBC flags any JDBC
   URL at all.

For the second case redaction widens one step at a time, and only as far as
needed for trufflehog to stop reporting the credential. First the secret
value, then the credential field (`user:REDACTED` becomes `REDACTED`,
`Password=REDACTED` becomes `REDACTED`), then the detector's whole match:

```
postgres://app:s3cr3t@db/app      pass 1 →  postgres://app:REDACTED@db/app
                                  pass 2 →  postgres://REDACTED@db/app
jdbc:postgresql://db/app?user=app&password=s3cr3t
                                  pass 1 →  ...&password=REDACTED
                                  pass 2 →  ...&REDACTED
                                  pass 3 →  REDACTED   (JDBC reports any JDBC URL)
```

Connection-string fields are only widened in connection strings. In JSON,
YAML or code, dropping a key would break the syntax, so nothing is widened
there.

### Residual findings

A few detectors match structure regardless of the secret in it. GCP reports
any JSON with an `auth_provider_x509_cert_url` key, GCP application default
credentials any JSON with a `client_secret` key, and the Docker, LDAP and
DotDigital detectors pair keywords with whatever value follows. Once their
secrets read `REDACTED`, trufflehog may still report them. These are listed
as `residual`. They hold no secret material, and widening further would have
to destroy the surrounding document, so they do not fail the command.

## Limitations

- **Compressed or encrypted storage.** trufflehog finds secrets inside zip,
  jar, gzip and similar files, but their bytes cannot be redacted in place.
  These files are reported as unredactable (exit status 1) unless
  `--remove-unredactable` deletes them.
- **Git history** is not redacted. A redacted checkout's `.git` directory
  still holds every secret ever committed (compressed). Hand over an export
  without `.git`, as in the pipeline example above.
- **Detectors that do not report their secret** cannot be redacted. For
  example, a result made only of identifiers. Redaction then fails closed.
  The ClickHelp detector had this bug and is fixed in this fork (see
  Maintaining the fork).
- **Files outside the given paths are never touched.** Files are read,
  written and removed through `os.Root` opened on the paths passed to
  `redact`. A finding in a symlink, or in a file reached through a symlinked
  directory or junction that leads elsewhere, is reported as unredactable.
  So is a file replaced while it is being redacted. Rewritten files keep their
  permission bits, but setuid/setgid bits and ownership are not preserved.
- **Large inputs.** Decoded views take about nine bytes of memory per input
  byte, so they are only built for inputs up to 4 MiB. Larger files are
  searched as plain text and base64 only; a secret there in another encoding
  is reported as unredactable.

### How files are rewritten

A redacted file is written to a new file next to it, which then replaces the
original by a rename. A crash never leaves a half-written file, and other hard
links to the file keep their content. None of this needs a privilege, also not
on Windows, where `redact --in-place` runs as a standard, non-elevated user
(no `SeSecurityPrivilege`, `SeBackupPrivilege` or administrator rights):

- Read-only files are made writable for the rename and read-only again after.
- A file another process holds open briefly (a virus scanner, a search
  indexer) is retried for about half a second.
- Where the new file cannot be created or renamed for lack of permission, as
  in a directory the user may change files in but not add files to, a file
  without other hard links has its content overwritten in place instead.

The rewritten file gets the permissions of the original but its owner, and on
Windows the ACL its directory passes on, rather than a copy of the original's
ACL.

## Testing

All tests live in `pkg/redact`:

| Test | What it covers |
|---|---|
| `TestRedact*`, `TestIdentifierParts` | The rules above, one case each. |
| `TestRun*`, `TestReadSameRejectsReplacedFiles`, `TestRedactLargeInputFailsClosed` | Files outside the given paths, including through symlinked directories and junctions, are never read, written or removed; replaced files are refused; oversized inputs fail closed. |
| `TestRedactFile*` | Rewriting read-only files, files another process holds open, and files in a directory the user may not add files to. |
| `TestRedactDetectorCorpus` | Redacts the example inputs of every detector's own tests: 3,662 inputs harvested from `pkg/detectors/**/*_test.go` (static evaluation of the `input:` fields, plus the raw test files), reaching 896 of 899 detectors. For each input, every detector is run, then redaction and rescanning repeat as in the CLI. It checks that no detector reports anything but residual findings afterwards, that every finding was located, that no distinctive secret survives, and that no byte outside a reported value was overwritten. It also fails on `SecretParts` keys that are not classified. |
| `TestRedactEngineCorpus` | Two inputs per detector, stored plain, base64, UTF-16LE, `\u`-escaped, HTML-escaped and as a JSON string (10,204 files), redacted through the real engine and every decoder with the same `Run` loop as the CLI. |
| `TestRedactEngineArchives` | A secret in a zip is unredactable and removed with `RemoveUnredactable`; a tar is redacted in place and stays readable. |
| `TestDetectorFeatureFlagsComplete` | The tests enable the same feature-gated detectors as the CLI. |
| `scripts/redaction-e2e.sh` | Acceptance test on [OWASP WrongSecrets](https://github.com/OWASP/wrongsecrets): trufflehog finds secrets, `redact --in-place` succeeds, and trufflehog then finds nothing, with default settings and with false positives and ignore tags included. |

```bash
go test ./pkg/redact/                                     # unit tests (seconds)
TRUFFLEHOG_REDACT_CORPUS=1 go test ./pkg/redact/ -v       # corpus tests (minutes)
TRUFFLEHOG_REDACT_CORPUS=1 REDACT_CORPUS_REPORT=report.md go test ./pkg/redact/ -run DetectorCorpus
scripts/redaction-e2e.sh /tmp/e2e
```

GitHub's Windows runners run as an administrator, so CI runs the Windows unit
tests and the WrongSecrets test through `hack/lowpriv`, which starts a command
with a restricted token: no privilege but `SeChangeNotifyPrivilege`, the
Administrators group deny-only, medium integrity, i.e. what a standard user
has. `hack/lowpriv/check-token.ps1` asserts that before the tests run. The
same works locally:

```powershell
go build -o lowpriv.exe ./hack/lowpriv
./lowpriv.exe whoami /priv
```

To see how a detector's inputs are redacted, pass by pass:

```bash
TRUFFLEHOG_REDACT_CORPUS=1 REDACT_DEBUG_DETECTOR=postgres REDACT_DEBUG_DIFF=1 go test ./pkg/redact/ -run CorpusDebug -v
```

## Maintaining the fork

### Footprint

The feature lives in new files, so merging upstream cannot conflict with it:

| Path | Purpose |
|---|---|
| `pkg/redact/` | The redaction library and its tests. |
| `main_redact.go` | The `redact` command (same `main` package as `main.go`). |
| `scripts/redaction-e2e.sh` | WrongSecrets acceptance test. |
| `hack/lowpriv/` | Runs commands as a standard Windows user, for CI. |
| `.github/workflows/redaction.yml` | Fork CI: unit, corpus, WrongSecrets (Linux and unprivileged Windows) and footprint checks. |
| `.github/workflows/upstream-sync.yml`, `.github/sync-issue.sh` | Merges upstream `main` and lands it when the CI passes. |
| `.github/workflows/redaction-release.yml` | Windows release builds. |
| `.github/redaction-footprint.txt`, `docs/redaction.md`, `.github/README.md` | This documentation, the footprint list and the repository front page (GitHub shows `.github/README.md` instead of upstream's `README.md`). |

Only these upstream files are modified, and the `footprint` CI job fails if
any other one is:

- `main.go`: one line. `run()` calls `runScan` instead of `runSingleScan`.
  `runScan`, defined in `main_redact.go`, handles `redact` and passes every
  other command through.
- `pkg/detectors/clickhelp/clickhelp.go`: one line. Unverified results now
  include the API key in `SecretParts`, so it can be redacted. This is an
  upstream bug and should be contributed upstream. Drop the change once
  upstream has it.

`main_redact.go` also forces `--no-update`. Upstream release binaries replace
themselves with the latest upstream release, which would silently swap a fork
build for one without `redact`.

### Branches

The fork's `main` is upstream's `main` plus the fork's commits. Upstream is
merged into it, not rebased, so the published history stays stable.

### Syncing with upstream

`.github/workflows/upstream-sync.yml` runs every six hours and on demand
(`workflow_dispatch`). It merges upstream `main` into `sync/upstream` and runs
the whole fork CI (`redaction.yml`) on the merge. When everything passes,
`main` is fast-forwarded to the merge and any open sync issue is closed; when
upstream has published a new version since the fork's last release, Windows
builds are released too. When the merge conflicts or a check fails, `main`
keeps its last good state and an issue labelled `upstream-sync` says why.

The default `GITHUB_TOKEN` may not push commits that change workflow files,
which upstream merges sometimes do; the sync then opens an issue asking for a
`SYNC_TOKEN` secret. Create a fine-grained personal access token for this
repository only, with read and write access to contents, issues and
workflows, and store it as the repository secret `SYNC_TOKEN`.

Upstream's own workflows (`codeql-analysis`, `lint`, `release`, `test`, ...)
come along with every merge. They are disabled in the repository's Actions
settings, which merges do not change, so they do not run here.

To sync by hand:

```bash
git remote add upstream https://github.com/trufflesecurity/trufflehog.git
git fetch upstream main
git merge upstream/main
go build ./... && go test ./pkg/redact/ && TRUFFLEHOG_REDACT_CORPUS=1 go test ./pkg/redact/
scripts/redaction-e2e.sh /tmp/e2e
```

Resolving conflicts:

- `main.go`: keep upstream's version and re-apply the hook. The call
  `metrics, err := runSingleScan(ctx, cmd, engConf)` in `run()` becomes
  `runScan(ctx, cmd, engConf)`. If upstream renamed `runSingleScan`,
  `filesystemScan`, `filesystemPaths` or the other `main.go` variables that
  `main_redact.go` uses, compilation fails and points at them.
- `clickhelp.go`: if upstream fixed the bug, take upstream's version and
  remove the file from `.github/redaction-footprint.txt`.

What a failing check after a sync means:

| Failure | Action |
|---|---|
| `TestDetectorFeatureFlagsComplete` | Upstream added a detector feature flag. Add it to `detectorFeatureFlags` in `pkg/redact/features_test.go`. |
| ``SecretParts key "x" ... is neither in secretParts nor identifierParts`` | A detector reports a new credential part. Decide whether it is secret, and add it to `secretParts` in `pkg/redact/corpus_test.go` or to `identifierParts` in `pkg/redact/targets.go`. Until then it is redacted. |
| `TestRedactDetectorCorpus` reports a detector | A new or changed detector reports its secret in a form redaction does not handle. Investigate with `REDACT_DEBUG_DETECTOR`. Fix it in `pkg/redact`, or upstream when the detector does not report its secret. |
| Coverage below 90% | Upstream changed how detector tests are written, and the input harvester (`harvestDir` in `corpus_test.go`) needs to learn the new form. |
| `footprint` | A change touched an upstream file. Move it to a new file, or justify it in the footprint list and this document. |
| Build errors in `main_redact.go` | Upstream changed `main.go` or `engine.Config`. Adapt the command. |

### Releasing

`.github/workflows/redaction-release.yml` builds `trufflehog.exe` for Windows
amd64 and arm64 like upstream does (`CGO_ENABLED=0`), zips each with
`LICENSE` and this document, tests the amd64 zip by redacting WrongSecrets in
place as a standard user, and publishes a GitHub release with the zips and
their SHA-256 checksums. Releases are named
`<latest upstream release>-redact.<fork commit>`, e.g. `v3.99.7-redact.1a2b3c4d`.
The sync workflow runs it when upstream publishes a new version; run it by
hand from the Actions tab for any other release.

Other platforms build like upstream: `go build -o trufflehog .`, or the
upstream `Dockerfile`.
