# Helpers for upstream-sync.yml to keep one open issue per sync problem.
# Needs GH_TOKEN and GITHUB_REPOSITORY.

# Labels the issues so they can be found and closed again.
SYNC_LABEL=upstream-sync

# report_issue <title> <body>: opens an issue, or comments on the open one
# with the same title.
report_issue() {
  gh label create "$SYNC_LABEL" --repo "$GITHUB_REPOSITORY" --color d93f0b \
    --description "Problems keeping the fork in sync with upstream" 2>/dev/null || true
  local number
  number=$(gh issue list --repo "$GITHUB_REPOSITORY" --state open --label "$SYNC_LABEL" \
    --json number,title --jq ".[] | select(.title == \"$1\") | .number" | head -1)
  if [ -n "$number" ]; then
    gh issue comment "$number" --repo "$GITHUB_REPOSITORY" --body "$2"
  else
    gh issue create --repo "$GITHUB_REPOSITORY" --label "$SYNC_LABEL" --title "$1" --body "$2"
  fi
}

# resolve_issues <comment>: closes every open sync issue.
resolve_issues() {
  gh issue list --repo "$GITHUB_REPOSITORY" --state open --label "$SYNC_LABEL" --json number --jq '.[].number' |
    while read -r number; do
      gh issue close "$number" --repo "$GITHUB_REPOSITORY" --comment "$1"
    done
}
