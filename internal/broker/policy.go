package broker

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const maxRESTSemanticBodyBytes = 1 << 20

const (
	grantActionsWrite     = "actions.write"
	grantChecksWrite      = "checks.write"
	grantContentsWrite    = "contents.write"
	grantDeploymentsWrite = "deployments.write"
	grantObjectsDelete    = "objects.delete"
	grantReleasesWrite    = "releases.write"
)

type restRoute struct {
	method  string
	pattern string
	grant   string
}

// restRoutes is intentionally exhaustive. New GitHub endpoints fail closed until
// their repository scope and identifier provenance have been reviewed.
var restRoutes = []restRoute{
	{http.MethodGet, "", ""},
	{http.MethodGet, "readme", ""},
	{http.MethodGet, "actions/workflows", ""}, {http.MethodGet, "actions/workflows/:", ""}, {http.MethodGet, "actions/workflows/:/runs", ""},
	{http.MethodGet, "actions/runs", ""}, {http.MethodGet, "actions/runs/:", ""}, {http.MethodGet, "actions/runs/:/jobs", ""}, {http.MethodGet, "actions/runs/:/logs", ""},
	{http.MethodGet, "actions/runs/:/attempts/:", ""}, {http.MethodGet, "actions/runs/:/attempts/:/jobs", ""}, {http.MethodGet, "actions/runs/:/attempts/:/logs", ""},
	{http.MethodGet, "actions/jobs/:", ""}, {http.MethodGet, "actions/jobs/:/logs", ""}, {http.MethodGet, "actions/artifacts", ""},
	{http.MethodGet, "actions/artifacts/:", ""}, {http.MethodGet, "actions/artifacts/:/zip", ""}, {http.MethodGet, "actions/runs/:/artifacts", ""}, {http.MethodGet, "actions/caches", ""},
	{http.MethodGet, "check-runs/:", ""}, {http.MethodGet, "check-runs/:/annotations", ""}, {http.MethodGet, "check-suites/:", ""},
	{http.MethodGet, "commits", ""}, {http.MethodGet, "commits/:", ""}, {http.MethodGet, "commits/:/comments", ""}, {http.MethodGet, "commits/:/pulls", ""},
	{http.MethodGet, "commits/:/branches-where-head", ""}, {http.MethodGet, "commits/:/check-runs", ""}, {http.MethodGet, "commits/:/check-suites", ""},
	{http.MethodGet, "commits/:/status", ""}, {http.MethodGet, "commits/:/statuses", ""}, {http.MethodGet, "contents/**", ""},
	{http.MethodGet, "deployments", ""}, {http.MethodGet, "deployments/:", ""}, {http.MethodGet, "deployments/:/statuses", ""},
	{http.MethodGet, "git/blobs/:", ""}, {http.MethodGet, "git/commits/:", ""}, {http.MethodGet, "git/trees/:", ""}, {http.MethodGet, "git/tags/:", ""},
	{http.MethodGet, "git/ref/**", ""}, {http.MethodGet, "git/refs", ""}, {http.MethodGet, "git/matching-refs/**", ""},
	{http.MethodGet, "issues", ""}, {http.MethodGet, "issues/events", ""}, {http.MethodGet, "issues/:", ""}, {http.MethodGet, "issues/:/comments", ""},
	{http.MethodGet, "issues/:/events", ""}, {http.MethodGet, "issues/:/timeline", ""}, {http.MethodGet, "issues/:/labels", ""}, {http.MethodGet, "issues/:/assignees", ""},
	{http.MethodGet, "issues/comments/:", ""}, {http.MethodGet, "issues/events/:", ""},
	{http.MethodGet, "labels", ""}, {http.MethodGet, "labels/:", ""}, {http.MethodGet, "milestones", ""}, {http.MethodGet, "milestones/:", ""}, {http.MethodGet, "milestones/:/labels", ""},
	{http.MethodGet, "pulls", ""}, {http.MethodGet, "pulls/:", ""}, {http.MethodGet, "pulls/:/commits", ""}, {http.MethodGet, "pulls/:/files", ""},
	{http.MethodGet, "pulls/:/comments", ""}, {http.MethodGet, "pulls/:/reviews", ""}, {http.MethodGet, "pulls/:/reviews/:", ""}, {http.MethodGet, "pulls/:/requested_reviewers", ""},
	{http.MethodGet, "pulls/:/merge", ""}, {http.MethodGet, "pulls/comments/:", ""},
	{http.MethodGet, "releases", ""}, {http.MethodGet, "releases/latest", ""}, {http.MethodGet, "releases/tags/:", ""}, {http.MethodGet, "releases/:", ""},
	{http.MethodGet, "releases/:/assets", ""}, {http.MethodGet, "releases/assets/:", ""}, {http.MethodGet, "statuses/:", ""},
	{http.MethodGet, "traffic/clones", ""}, {http.MethodGet, "traffic/views", ""}, {http.MethodGet, "traffic/popular/paths", ""}, {http.MethodGet, "traffic/popular/referrers", ""},

	{http.MethodPost, "issues", ""}, {http.MethodPatch, "issues/:", ""}, {http.MethodPost, "issues/:/comments", ""},
	{http.MethodPatch, "issues/comments/:", ""}, {http.MethodDelete, "issues/comments/:", ""},
	{http.MethodPost, "issues/:/labels", ""}, {http.MethodPut, "issues/:/labels", ""}, {http.MethodDelete, "issues/:/labels", ""}, {http.MethodDelete, "issues/:/labels/:", ""},
	{http.MethodPost, "issues/:/assignees", ""}, {http.MethodDelete, "issues/:/assignees", ""}, {http.MethodPut, "issues/:/lock", ""}, {http.MethodDelete, "issues/:/lock", ""},
	{http.MethodPost, "issues/:/reactions", ""}, {http.MethodDelete, "issues/:/reactions/:", ""}, {http.MethodPost, "issues/comments/:/reactions", ""}, {http.MethodDelete, "issues/comments/:/reactions/:", ""},
	{http.MethodPost, "labels", ""}, {http.MethodPatch, "labels/:", ""}, {http.MethodDelete, "labels/:", ""},
	{http.MethodPost, "milestones", ""}, {http.MethodPatch, "milestones/:", ""}, {http.MethodDelete, "milestones/:", ""},
	{http.MethodPost, "pulls", ""}, {http.MethodPatch, "pulls/:", ""}, {http.MethodPut, "pulls/:/merge", ""},
	{http.MethodPost, "pulls/:/comments", ""}, {http.MethodPost, "pulls/:/comments/:/replies", ""}, {http.MethodPatch, "pulls/comments/:", ""}, {http.MethodDelete, "pulls/comments/:", ""},
	{http.MethodPost, "pulls/:/reviews", ""}, {http.MethodDelete, "pulls/:/reviews/:", ""}, {http.MethodPost, "pulls/:/reviews/:/events", ""}, {http.MethodPut, "pulls/:/reviews/:/dismissals", ""},
	{http.MethodPost, "pulls/:/requested_reviewers", ""}, {http.MethodDelete, "pulls/:/requested_reviewers", ""},
	{http.MethodPost, "pulls/comments/:/reactions", ""}, {http.MethodDelete, "pulls/comments/:/reactions/:", ""},

	{http.MethodPost, "actions/workflows/:/dispatches", grantActionsWrite}, {http.MethodPut, "actions/workflows/:/enable", grantActionsWrite}, {http.MethodPut, "actions/workflows/:/disable", grantActionsWrite},
	{http.MethodPost, "actions/runs/:/rerun", grantActionsWrite}, {http.MethodPost, "actions/runs/:/rerun-failed-jobs", grantActionsWrite}, {http.MethodPost, "actions/runs/:/cancel", grantActionsWrite},
	{http.MethodPost, "actions/runs/:/force-cancel", grantActionsWrite}, {http.MethodPost, "actions/jobs/:/rerun", grantActionsWrite},
	{http.MethodDelete, "actions/runs/:", grantActionsWrite}, {http.MethodDelete, "actions/runs/:/logs", grantActionsWrite}, {http.MethodDelete, "actions/artifacts/:", grantActionsWrite},
	{http.MethodDelete, "actions/caches", grantActionsWrite}, {http.MethodDelete, "actions/caches/:", grantActionsWrite},
	{http.MethodPost, "check-runs", grantChecksWrite}, {http.MethodPatch, "check-runs/:", grantChecksWrite}, {http.MethodPost, "check-suites", grantChecksWrite}, {http.MethodPost, "check-suites/:/rerequest", grantChecksWrite},
	{http.MethodPut, "contents/**", grantContentsWrite}, {http.MethodDelete, "contents/**", grantContentsWrite},
	{http.MethodPost, "git/blobs", grantContentsWrite}, {http.MethodPost, "git/commits", grantContentsWrite}, {http.MethodPost, "git/trees", grantContentsWrite}, {http.MethodPost, "git/tags", grantContentsWrite},
	{http.MethodPost, "git/refs", grantContentsWrite}, {http.MethodPatch, "git/refs/**", grantContentsWrite},
	{http.MethodPost, "deployments", grantDeploymentsWrite}, {http.MethodPost, "deployments/:/statuses", grantDeploymentsWrite},
	{http.MethodPost, "releases", grantReleasesWrite}, {http.MethodPost, "releases/generate-notes", grantReleasesWrite}, {http.MethodPatch, "releases/:", grantReleasesWrite},
	{http.MethodDelete, "releases/:", grantReleasesWrite}, {http.MethodDelete, "releases/assets/:", grantReleasesWrite}, {http.MethodPost, "statuses/:", grantChecksWrite},
}

// IsKnownGrant rejects misspelled or unsupported authority at issue time.
func IsKnownGrant(grant string) bool {
	switch grant {
	case grantActionsWrite, grantChecksWrite, grantContentsWrite, grantDeploymentsWrite, grantObjectsDelete, grantReleasesWrite:
		return true
	default:
		return false
	}
}

func (p Policy) allows(grant string) bool {
	return p.Grants != nil && p.Grants[grant]
}

func authorizeREST(method string, path []string, policy Policy) bool {
	if isHardDeniedREST(path) {
		return false
	}
	if method == http.MethodHead {
		method = http.MethodGet
	}
	for _, route := range restRoutes {
		if route.method != method || !matchRESTPath(route.pattern, path) {
			continue
		}
		if method == http.MethodDelete && !policy.allows(grantObjectsDelete) {
			return false
		}
		return route.grant == "" || policy.allows(route.grant)
	}
	return false
}

func isHardDeniedREST(path []string) bool {
	if len(path) == 0 {
		return false
	}
	switch path[0] {
	case "actions":
		return len(path) > 1 && (path[1] == "secrets" || path[1] == "variables")
	case "collaborators", "environments", "hooks", "invitations", "keys", "rulesets", "secret-scanning", "security-advisories", "teams", "vulnerability-alerts":
		return true
	case "issues":
		return containsRESTSegment(path, "transfer", "sub_issues", "sub-issues", "dependencies", "blocked_by", "blocked-by")
	case "pulls":
		return containsRESTSegment(path, "update-branch")
	}
	return false
}

func containsRESTSegment(path []string, denied ...string) bool {
	for _, segment := range path {
		for _, value := range denied {
			if segment == value {
				return true
			}
		}
	}
	return false
}

func matchRESTPath(pattern string, path []string) bool {
	if pattern == "" {
		return len(path) == 0
	}
	parts := strings.Split(pattern, "/")
	for index, part := range parts {
		if part == "**" {
			return index == len(parts)-1
		}
		if index >= len(path) || (part != ":" && part != path[index]) {
			return false
		}
	}
	return len(parts) == len(path)
}

func validBrokerPath(reqPath, escapedPath string) bool {
	lowerEscaped := strings.ToLower(escapedPath)
	if strings.Contains(lowerEscaped, "%2f") || strings.Contains(lowerEscaped, "%5c") || strings.Contains(lowerEscaped, "%2e") {
		return false
	}
	if strings.Contains(reqPath, "\\") || strings.Contains(reqPath, "//") {
		return false
	}
	for _, segment := range strings.Split(reqPath, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func authorizeRESTBody(req *http.Request, path []string, repository Repository, policy Policy) (int, errorResponse) {
	if len(path) == 0 {
		return 0, errorResponse{}
	}
	var refField string
	var pathRef string
	requireTag := false
	requireBoundBranch := false
	releaseEdit := false
	switch path[0] {
	case "actions":
		if len(path) < 4 || path[1] != "workflows" || path[3] != "dispatches" || req.Method != http.MethodPost {
			return 0, errorResponse{}
		}
		refField = "ref"
	case "contents":
		if req.Method != http.MethodPut && req.Method != http.MethodDelete {
			return 0, errorResponse{}
		}
		refField = "branch"
	case "deployments":
		if len(path) != 1 || req.Method != http.MethodPost {
			return 0, errorResponse{}
		}
		refField = "ref"
	case "releases":
		if len(path) == 1 && req.Method == http.MethodPost {
			refField = "target_commitish"
			requireTag = true
		} else if len(path) == 2 && req.Method == http.MethodPatch {
			refField = "target_commitish"
			releaseEdit = true
		} else {
			return 0, errorResponse{}
		}
	case "git":
		if len(path) == 2 && path[1] == "refs" && req.Method == http.MethodPost {
			refField = "ref"
		} else if len(path) >= 3 && path[1] == "refs" && req.Method == http.MethodPatch {
			pathRef = "refs/" + strings.Join(path[2:], "/")
		} else {
			return 0, errorResponse{}
		}
	case "pulls":
		if len(path) != 1 || req.Method != http.MethodPost {
			return 0, errorResponse{}
		}
		refField = "head"
		requireBoundBranch = true
	default:
		return 0, errorResponse{}
	}
	if pathRef != "" {
		if !authorizeRESTRef(pathRef, repository.DefaultBranch, policy.Git) {
			return http.StatusForbidden, errorResponse{Message: "request ref is not allowed", Code: "PGH_REF_DENIED"}
		}
		return 0, errorResponse{}
	}
	if req.Body == nil || req.Body == http.NoBody {
		return http.StatusBadRequest, errorResponse{Message: "request body is invalid", Code: "PGH_BODY_INVALID"}
	}

	data, err := io.ReadAll(io.LimitReader(req.Body, maxRESTSemanticBodyBytes+1))
	if err != nil || len(data) > maxRESTSemanticBodyBytes {
		return http.StatusBadRequest, errorResponse{Message: "request body is invalid", Code: "PGH_BODY_INVALID"}
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return http.StatusBadRequest, errorResponse{Message: "request body is invalid", Code: "PGH_BODY_INVALID"}
	}
	if releaseEdit {
		_, changesTag := fields["tag_name"]
		_, changesTarget := fields["target_commitish"]
		if !changesTag && !changesTarget {
			return 0, errorResponse{}
		}
		requireTag = true
	}
	if requireTag && !policy.Git.Tags {
		return http.StatusForbidden, errorResponse{Message: "tag creation is not allowed", Code: "PGH_REF_DENIED"}
	}
	ref := repository.DefaultBranch
	if raw, ok := fields[refField]; ok {
		if err := json.Unmarshal(raw, &ref); err != nil || ref == "" {
			return http.StatusBadRequest, errorResponse{Message: "request ref is invalid", Code: "PGH_BODY_INVALID"}
		}
	} else if requireBoundBranch {
		return http.StatusBadRequest, errorResponse{Message: "request ref is invalid", Code: "PGH_BODY_INVALID"}
	}
	if requireBoundBranch {
		if strings.ContainsAny(ref, ":\x00\r\n") || strings.HasPrefix(ref, "refs/") {
			return http.StatusForbidden, errorResponse{Message: "request ref is not allowed", Code: "PGH_REF_DENIED"}
		}
		return 0, errorResponse{}
	}
	if !authorizeRESTRef(ref, repository.DefaultBranch, policy.Git) {
		return http.StatusForbidden, errorResponse{Message: "request ref is not allowed", Code: "PGH_REF_DENIED"}
	}
	return 0, errorResponse{}
}

func authorizeRESTRef(ref, defaultBranch string, policy GitPolicy) bool {
	if strings.HasPrefix(ref, "refs/tags/") {
		return policy.Tags
	}
	if strings.HasPrefix(ref, "refs/") && !strings.HasPrefix(ref, "refs/heads/") {
		return false
	}
	ref = strings.TrimPrefix(ref, "refs/heads/")
	if ref == "" || strings.ContainsAny(ref, ":\x00\r\n") {
		return false
	}
	return authorizeGitRef(gitRefCommand{newOID: strings.Repeat("1", 40), ref: "refs/heads/" + ref}, defaultBranch, policy)
}
