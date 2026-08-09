#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "${repo_root}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${repo_root}/.env"
  set +a
fi

: "${GH_TOKEN:?GH_TOKEN must be set directly or in .env}"
export PGH_LIVE_TOKEN="${GH_TOKEN}"
unset GH_TOKEN

if [[ -z "${PGH_LIVE_REPO:-}" ]]; then
  origin="$(git -C "${repo_root}" remote get-url origin)"
  case "${origin}" in
    https://github.com/*)
      PGH_LIVE_REPO="${origin#https://github.com/}"
      ;;
    git@github.com:*)
      PGH_LIVE_REPO="${origin#git@github.com:}"
      ;;
    *)
      printf 'Set PGH_LIVE_REPO=OWNER/REPO; origin is not a github.com URL.\n' >&2
      exit 2
      ;;
  esac
  PGH_LIVE_REPO="${PGH_LIVE_REPO%.git}"
  export PGH_LIVE_REPO
fi

cd "${repo_root}"

go test ./cmd/pgh ./internal/pghcmd \
  -run '^(TestPGHCommandSurfaceIsDiscoverable|TestRunnableCommandAuditManifestMatchesLiveCases)$' \
  -count=1
go test ./internal/pghcmd -run '^TestLivePGH' -count=1 -v
go test ./internal/broker \
  -run '^TestLive(GitHubReadCompatibility|GitSmartHTTPReadCompatibility)$' \
  -count=1 -v

if [[ "${PGH_LIVE_ALLOW_WRITES:-}" == "1" ]]; then
  : "${PGH_LIVE_DEFAULT_BRANCH:?PGH_LIVE_DEFAULT_BRANCH is required when PGH_LIVE_ALLOW_WRITES=1}"
  go test ./internal/broker \
    -run '^TestLiveGitSmartHTTP(NonDefaultPush|TagPush)Compatibility$' \
    -count=1 -v
else
  printf '%s\n' 'Live write checks skipped; set PGH_LIVE_ALLOW_WRITES=1 and PGH_LIVE_DEFAULT_BRANCH to enable them.'
fi
