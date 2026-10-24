#!/usr/bin/env bash
# End-to-end check of `trufflehog redact` against OWASP WrongSecrets
# (https://github.com/OWASP/wrongsecrets), a project full of deliberately
# leaked secrets:
#
#   1. trufflehog finds secrets in a fresh checkout,
#   2. `trufflehog redact --in-place` redacts all of them,
#   3. trufflehog finds nothing in the result, both with its default settings
#      and with false positives and trufflehog:ignore lines included.
#
# Usage: scripts/redaction-e2e.sh [work-dir]
#   TRUFFLEHOG       trufflehog binary to test (default: build ./ into work-dir)
#   WRONGSECRETS_REF branch or tag of wrongsecrets to clone (default: master)
set -euo pipefail

work=${1:-$(mktemp -d)}
mkdir -p "$work"
repo_root=$(cd "$(dirname "$0")/.." && pwd)

if [[ -z "${TRUFFLEHOG:-}" ]]; then
  TRUFFLEHOG="$work/trufflehog"
  (cd "$repo_root" && go build -o "$TRUFFLEHOG" .)
fi
"$TRUFFLEHOG" redact --help >/dev/null

target="$work/wrongsecrets"
if [[ ! -d "$target" ]]; then
  git clone --quiet --depth 1 --branch "${WRONGSECRETS_REF:-master}" \
    https://github.com/OWASP/wrongsecrets.git "$target"
fi

# scan [flags...]: prints the number of findings; trufflehog's --fail exit
# code (183) says whether there were any.
scan() {
  local out status=0
  out=$("$TRUFFLEHOG" filesystem "$target" --no-verification --no-update --json --fail "$@" 2>/dev/null) || status=$?
  if [[ $status -ne 0 && $status -ne 183 ]]; then
    echo "trufflehog filesystem failed with exit code $status" >&2
    exit 1
  fi
  grep -c '"DetectorName"' <<<"$out" || true
}
strict=(--results=verified,unverified,unknown,filtered_unverified --no-ignore-tag)

before=$(scan)
echo "before redaction: $before findings ($(scan "${strict[@]}") including false positives and ignored lines)"
if [[ $before -eq 0 ]]; then
  echo "FAIL: expected trufflehog to find secrets in wrongsecrets" >&2
  exit 1
fi

"$TRUFFLEHOG" redact "$target" --in-place --no-update > "$work/redact.log" 2> "$work/redact.err"
echo "redact: $(grep -c '^redacted' "$work/redact.log") redactions in $(grep '^redacted' "$work/redact.log" | awk '{print $2}' | sed 's/:[0-9]*$//' | sort -u | wc -l) files"

after=$(scan)
after_strict=$(scan "${strict[@]}")
echo "after redaction: $after findings ($after_strict including false positives and ignored lines)"
if [[ $after -ne 0 || $after_strict -ne 0 ]]; then
  echo "FAIL: trufflehog still finds secrets after redaction" >&2
  "$TRUFFLEHOG" filesystem "$target" --no-verification --no-update "${strict[@]}" >&2 || true
  exit 1
fi
echo "PASS"
