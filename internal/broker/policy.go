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
	if len(path) == 0 {
		return method == http.MethodGet || method == http.MethodHead
	}

	resource := path[0]
	if isHardDeniedREST(path) {
		return false
	}

	if method == http.MethodGet || method == http.MethodHead {
		switch resource {
		case "actions", "check-runs", "check-suites", "commits", "contents", "deployments", "git", "issues", "labels", "milestones", "pulls", "releases", "statuses", "traffic":
			return true
		default:
			return false
		}
	}

	if method == http.MethodDelete && !policy.allows(grantObjectsDelete) {
		return false
	}

	switch resource {
	case "issues", "labels", "milestones":
		return method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut || method == http.MethodDelete
	case "pulls":
		return method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut || method == http.MethodDelete
	case "actions":
		return policy.allows(grantActionsWrite) && isMutationMethod(method)
	case "check-runs", "check-suites", "statuses":
		return policy.allows(grantChecksWrite) && isMutationMethod(method)
	case "contents", "git":
		return policy.allows(grantContentsWrite) && isMutationMethod(method)
	case "deployments":
		return policy.allows(grantDeploymentsWrite) && isMutationMethod(method)
	case "releases":
		return policy.allows(grantReleasesWrite) && isMutationMethod(method)
	default:
		return false
	}
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
	default:
		return false
	}
}

func isMutationMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
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
	if len(path) == 0 || req.Body == nil || req.Body == http.NoBody {
		return 0, errorResponse{}
	}
	var refField string
	requireTag := false
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
		if req.Method != http.MethodPost {
			return 0, errorResponse{}
		}
		refField = "ref"
	case "releases":
		if len(path) != 1 || req.Method != http.MethodPost {
			return 0, errorResponse{}
		}
		refField = "target_commitish"
		requireTag = true
	default:
		return 0, errorResponse{}
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
	if requireTag && !policy.Git.Tags {
		return http.StatusForbidden, errorResponse{Message: "tag creation is not allowed", Code: "PGH_REF_DENIED"}
	}
	ref := repository.DefaultBranch
	if raw, ok := fields[refField]; ok {
		if err := json.Unmarshal(raw, &ref); err != nil || ref == "" {
			return http.StatusBadRequest, errorResponse{Message: "request ref is invalid", Code: "PGH_BODY_INVALID"}
		}
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
	ref = strings.TrimPrefix(ref, "refs/heads/")
	if ref == "" || strings.ContainsAny(ref, "\x00\r\n") {
		return false
	}
	return authorizeGitRef(gitRefCommand{newOID: strings.Repeat("1", 40), ref: "refs/heads/" + ref}, defaultBranch, policy)
}
