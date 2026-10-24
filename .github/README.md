# trufflehog with in-place redaction

A fork of [trufflehog](https://github.com/trufflesecurity/trufflehog) that adds
`trufflehog redact`: it overwrites the secrets trufflehog finds with
`REDACTED`, in the files they were found in, so that source code can be handed
to a scanner or anyone else that must not see credentials.

```bash
trufflehog redact ./src              # report what would be redacted
trufflehog redact ./src --in-place   # redact
```

- Only the secret is overwritten: identifiers next to it (key IDs, users,
  hosts) and the surrounding text stay as they are. Secrets stored as base64,
  UTF-16, escape sequences or HTML are redacted in that form.
- It is tested against the example inputs of every trufflehog detector, and
  against [OWASP WrongSecrets](https://github.com/OWASP/wrongsecrets):
  trufflehog finds secrets there before, and none after
  `redact --in-place`.
- It fails closed: a secret that cannot be redacted (inside a zip, say) makes
  the command exit with status 1.
- On Windows it needs no administrator rights.

**Windows:** download `trufflehog_<version>_windows_amd64.zip` from the
[releases](https://github.com/cxosmobb/trufflehog-with-inline-redact-claude/releases),
unpack it and run `trufflehog.exe redact <path> --in-place`.

**Elsewhere:** `go build -o trufflehog .`

Everything else is upstream trufflehog, merged from upstream `main` every six
hours once the redaction CI passes on the merge. See
[docs/redaction.md](../docs/redaction.md) for how redaction works, its
limitations and how the fork is maintained, and upstream's
[README](../README.md) for trufflehog itself.
