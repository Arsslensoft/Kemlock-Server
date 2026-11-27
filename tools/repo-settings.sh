#!/usr/bin/env bash
# Applies the repository settings that cannot live in a file, with `gh api`. Run it once as a
# repository admin after the CI files land, and again whenever it changes: every step sets the
# wanted state, so a second run changes nothing.
#
#   tools/repo-settings.sh                       # Arsslensoft/Kemlock-Server
#   tools/repo-settings.sh --dry-run             # print what it would send, change nothing
#   tools/repo-settings.sh --repo owner/name
#
# Environment:
#   REQUIRED_APPROVALS=1       approvals a pull request needs (the owner bypasses it, see below)
#   REQUIRE_SIGNED_COMMITS=0   1 also requires signed (GPG or SSH) commits on main
#
# What it sets:
#   1. security: private vulnerability reporting, Dependabot alerts and security updates, secret
#      scanning with push protection;
#   2. merging: squash only, auto-merge allowed, branches deleted once merged;
#   3. Actions: a read-only default token, and Actions may approve pull requests (Dependabot's
#      auto-merge workflow needs that);
#   4. a ruleset on the default branch: pull request, approval (of the last push too), the required
#      checks (`ci-ok`, `DCO`, the PR title, dependency review, gitleaks and CodeQL), linear history, no
#      force push, no deletion;
#   4b. a ruleset on version tags (v1.2.3 and 1.2.3): only admins may create, move or delete one,
#      so a write token cannot cut a signed release from any commit;
#   5. the labels .github/labeler.yml and dependabot.yml use.
#
# The ruleset lets repository admins bypass it through a pull request only (never by pushing to
# main), because a sole maintainer cannot approve their own pull request. Remove the bypass actor
# below when there is a second maintainer.
#
# Needs the GitHub CLI, logged in (`gh auth login`) as an admin of the repository.
set -euo pipefail

repo="Arsslensoft/Kemlock-Server"
dry=0
approvals="${REQUIRED_APPROVALS:-1}"
signed="${REQUIRE_SIGNED_COMMITS:-0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) dry=1; shift ;;
    --repo) repo="${2:?--repo needs owner/name}"; shift 2 ;;
    -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "repo-settings: unknown argument: $1" >&2; exit 2 ;;
  esac
done
command -v gh >/dev/null || { echo "repo-settings: the GitHub CLI (gh) is needed" >&2; exit 2; }

failed=0
step() { echo; echo "==> $*"; }
ok() { echo "    ok: $*"; }
warn() { echo "    FAILED: $*" >&2; failed=1; }

# api METHOD PATH [json body on stdin]: sends it, or prints it with --dry-run.
# A call with no body is made with </dev/null.
api() {
  local method="$1" path="$2" body
  body="$(cat)"
  if [ "$dry" = 1 ]; then
    echo "    [dry run] $method /$path ${body:+with $(printf '%s' "$body" | tr -s ' \n' ' ')}"
    return 0
  fi
  if [ -n "$body" ]; then
    printf '%s' "$body" | gh api -X "$method" "$path" --input - >/dev/null
  else
    gh api -X "$method" "$path" >/dev/null
  fi
}

echo "Repository: $repo$([ "$dry" = 1 ] && echo ' (dry run)')"
if [ "$dry" = 0 ]; then
  gh api "repos/$repo" --jq '"    " + .full_name + ", default branch " + .default_branch + ", " + .visibility' \
    || { echo "repo-settings: cannot read $repo (is gh logged in with admin rights?)" >&2; exit 2; }
fi

# --- 1. Security -------------------------------------------------------------------------------
step "Private vulnerability reporting (the one way SECURITY.md takes reports)"
api PUT "repos/$repo/private-vulnerability-reporting" </dev/null && ok enabled || warn "private vulnerability reporting"

step "Dependabot alerts"
api PUT "repos/$repo/vulnerability-alerts" </dev/null && ok enabled || warn "Dependabot alerts"

step "Dependabot security updates"
api PUT "repos/$repo/automated-security-fixes" </dev/null && ok enabled || warn "Dependabot security updates"

step "Secret scanning and push protection"
api PATCH "repos/$repo" <<'JSON' && ok enabled || warn "secret scanning (free on public repositories; a private one needs GitHub Secret Protection)"
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
JSON

# --- 2. Merging --------------------------------------------------------------------------------
step "Squash merge only, auto-merge allowed, delete branches when merged"
api PATCH "repos/$repo" <<'JSON' && ok set || warn "merge settings"
{
  "allow_squash_merge": true,
  "allow_merge_commit": false,
  "allow_rebase_merge": false,
  "allow_auto_merge": true,
  "delete_branch_on_merge": true,
  "allow_update_branch": true,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "PR_BODY"
}
JSON

# --- 3. Actions --------------------------------------------------------------------------------
step "Actions: a read-only default token that may approve pull requests"
api PUT "repos/$repo/actions/permissions/workflow" <<'JSON' && ok set || warn "workflow permissions"
{
  "default_workflow_permissions": "read",
  "can_approve_pull_request_reviews": true
}
JSON

# --- 4. The ruleset on the default branch ------------------------------------------------------
step "Ruleset \"main\" on the default branch"
signature_rule=""
if [ "$signed" = 1 ]; then signature_rule=', { "type": "required_signatures" }'; fi
# integration_id 15368 is GitHub Actions: a status of the same name from anything else does not
# count.
ruleset="$(cat <<JSON
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": $approvals,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": true,
        "require_extra_approval_for_unattributed_changes": true,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "ci-ok", "integration_id": 15368 },
          { "context": "DCO", "integration_id": 15368 },
          { "context": "conventional title", "integration_id": 15368 },
          { "context": "review", "integration_id": 15368 },
          { "context": "scan", "integration_id": 15368 },
          { "context": "analyze (actions)", "integration_id": 15368 },
          { "context": "analyze (javascript-typescript)", "integration_id": 15368 },
          { "context": "analyze (rust)", "integration_id": 15368 }
        ]
      }
    }$signature_rule
  ]
}
JSON
)"
existing=""
if [ "$dry" = 0 ]; then
  existing="$(gh api "repos/$repo/rulesets" --jq '.[] | select(.name == "main") | .id' | head -n 1)"
fi
if [ -n "$existing" ]; then
  echo "    updating ruleset $existing"
  printf '%s' "$ruleset" | api PUT "repos/$repo/rulesets/$existing" && ok updated || warn "ruleset update"
else
  echo "    creating the ruleset"
  printf '%s' "$ruleset" | api POST "repos/$repo/rulesets" && ok created || warn "ruleset creation"
fi
echo "    (checks: ci-ok, DCO, conventional title, review, scan, analyze x3; approvals: $approvals, last push included; signed commits: $([ "$signed" = 1 ] && echo required || echo optional))"

# --- 4b. The ruleset on release tags -----------------------------------------------------------
# release.yml publishes a signed image on any version tag. Without this, anyone with write access
# can push a tag on any commit (even an unreviewed branch) and cut a release. Only repository
# admins (role 5) may create, move or delete a version tag; release.yml also refuses a tag that is
# not on the default branch.
step "Ruleset \"release tags\" on version tags"
tag_ruleset="$(cat <<'JSON'
{
  "name": "release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*", "refs/tags/[0-9]*"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "rules": [
    { "type": "creation" },
    { "type": "update" },
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
JSON
)"
tag_existing=""
if [ "$dry" = 0 ]; then
  tag_existing="$(gh api "repos/$repo/rulesets" --jq '.[] | select(.name == "release tags") | .id' | head -n 1)"
fi
if [ -n "$tag_existing" ]; then
  echo "    updating ruleset $tag_existing"
  printf '%s' "$tag_ruleset" | api PUT "repos/$repo/rulesets/$tag_existing" && ok updated || warn "tag ruleset update"
else
  echo "    creating the ruleset"
  printf '%s' "$tag_ruleset" | api POST "repos/$repo/rulesets" && ok created || warn "tag ruleset creation"
fi

# --- 5. Labels ---------------------------------------------------------------------------------
step "Labels used by .github/labeler.yml and .github/dependabot.yml"
label() {
  local name="$1" color="$2" description="$3"
  if [ "$dry" = 1 ]; then echo "    [dry run] label $name"; return 0; fi
  if gh label create "$name" --repo "$repo" --color "$color" --description "$description" --force >/dev/null; then
    echo "    ok: $name"
  else
    warn "label $name"
  fi
}
label rust dea584 "Rust crates"
label web 3178c6 "Web vault and admin console"
label crypto b60205 "Cryptography and byte formats"
label api 0e8a16 "HTTP APIs"
label docs 0075ca "Documentation"
label docker 0db7ed "Image and Dockerfile"
label deploy 5319e7 "Deployment recipes"
label ci 6e7781 "CI, release and tooling"
label tests fbca04 "Tests"
label dependencies 0366d6 "Dependency updates"
label javascript f1e05a "JavaScript and TypeScript dependencies"
label github-actions 000000 "GitHub Actions updates"
label security d93f0b "Security"
label stale ededed "No recent activity"
label pinned 1d76db "Exempt from the stale workflow"

echo
if [ "$failed" = 1 ]; then
  echo "repo-settings: some steps failed (see FAILED above); fix the cause and run it again." >&2
  exit 1
fi
echo "repo-settings: done. Still by hand: install the CodeRabbit GitHub App."
