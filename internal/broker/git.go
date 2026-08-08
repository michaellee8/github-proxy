package broker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxGitCommandBytes = 64 * 1024
	maxGitCommands     = 256
	maxLFSBatchBytes   = 1 << 20
)

type gitRefCommand struct {
	newOID string
	ref    string
}

func (h *handler) serveGit(w http.ResponseWriter, req *http.Request, session Session) {
	remainder, scopeStatus, scopeError := gitPath(req, session.Repository)
	if scopeError.Code != "" {
		writeJSON(w, scopeStatus, scopeError)
		return
	}

	body := req.Body
	switch {
	case req.Method == http.MethodGet && remainder == "info/refs":
		service := req.URL.Query().Get("service")
		if service != "git-upload-pack" && service != "git-receive-pack" {
			writeJSON(w, http.StatusForbidden, errorResponse{Message: "Git service is not allowed", Code: "PGH_POLICY_DENIED"})
			return
		}
		if service == "git-receive-pack" && !gitCanPush(session.Policy.Git) {
			writeJSON(w, http.StatusForbidden, errorResponse{Message: "Git push is not allowed", Code: "PGH_POLICY_DENIED"})
			return
		}
	case req.Method == http.MethodPost && remainder == "git-upload-pack":
	case req.Method == http.MethodPost && remainder == "git-receive-pack":
		prefix, commands, err := readReceiveCommands(req.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Message: "Git receive-pack request is invalid", Code: "PGH_GIT_INVALID"})
			return
		}
		for _, command := range commands {
			if !authorizeGitRef(command, session.Repository.DefaultBranch, session.Policy.Git) {
				writeJSON(w, http.StatusForbidden, errorResponse{Message: "Git ref update is not allowed", Code: "PGH_GIT_REF_DENIED"})
				return
			}
		}
		body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), req.Body))
	case strings.HasPrefix(remainder, "info/lfs/"):
		var err error
		body, err = authorizeLFS(req, remainder, session.Policy.Git)
		if err != nil {
			var policyError *lfsPolicyError
			if errors.As(err, &policyError) {
				writeJSON(w, http.StatusForbidden, errorResponse{Message: policyError.Error(), Code: "PGH_POLICY_DENIED"})
			} else {
				writeJSON(w, http.StatusBadRequest, errorResponse{Message: "Git LFS request is invalid", Code: "PGH_LFS_INVALID"})
			}
			return
		}
	default:
		writeJSON(w, http.StatusForbidden, errorResponse{Message: "Git operation is not allowed", Code: "PGH_POLICY_DENIED"})
		return
	}

	upstreamURL, err := gitUpstreamURL(session.Repository.UpstreamHost, req.URL)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Message: "upstream host is misconfigured", Code: "PGH_UPSTREAM_INVALID"})
		return
	}
	upstream, err := http.NewRequestWithContext(req.Context(), req.Method, upstreamURL.String(), body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Message: "failed to build upstream request", Code: "PGH_UPSTREAM_ERROR"})
		return
	}
	upstream.ContentLength = req.ContentLength
	copyEndToEndHeaders(upstream.Header, req.Header)
	upstream.SetBasicAuth("x-access-token", session.Repository.UpstreamToken)
	response, err := h.transport.RoundTrip(upstream)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Message: "GitHub request failed", Code: "PGH_UPSTREAM_ERROR"})
		return
	}
	defer response.Body.Close()
	copyEndToEndHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func gitPath(req *http.Request, repository Repository) (string, int, errorResponse) {
	if !validBrokerPath(req.URL.Path, req.URL.EscapedPath()) {
		return "", http.StatusBadRequest, errorResponse{Message: "request path is invalid", Code: "PGH_PATH_INVALID"}
	}
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")
	if len(parts) < 3 || !strings.HasSuffix(parts[1], ".git") {
		return "", http.StatusForbidden, errorResponse{Message: "Git repository path is invalid", Code: "PGH_POLICY_DENIED"}
	}
	name := strings.TrimSuffix(parts[1], ".git")
	if !strings.EqualFold(parts[0], repository.Owner) || !strings.EqualFold(name, repository.Name) {
		return "", http.StatusForbidden, errorResponse{Message: "repository is outside this capability", Code: "PGH_REPOSITORY_DENIED"}
	}
	return strings.Join(parts[2:], "/"), 0, errorResponse{}
}

func gitUpstreamURL(host string, requestURL *url.URL) (*url.URL, error) {
	parsed, err := url.Parse("https://" + host)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid Git upstream host")
	}
	parsed.Path = requestURL.Path
	parsed.RawQuery = requestURL.RawQuery
	return parsed, nil
}

func readReceiveCommands(body io.Reader) ([]byte, []gitRefCommand, error) {
	var prefix bytes.Buffer
	commands := make([]gitRefCommand, 0, 1)
	for len(commands) < maxGitCommands {
		header := make([]byte, 4)
		if _, err := io.ReadFull(body, header); err != nil {
			return nil, nil, err
		}
		prefix.Write(header)
		length, err := strconv.ParseUint(string(header), 16, 16)
		if err != nil {
			return nil, nil, err
		}
		if length == 0 {
			if len(commands) == 0 {
				return nil, nil, errors.New("receive-pack has no ref commands")
			}
			return prefix.Bytes(), commands, nil
		}
		if length < 4 || length > maxGitCommandBytes {
			return nil, nil, errors.New("invalid pkt-line length")
		}
		payload := make([]byte, int(length)-4)
		if _, err := io.ReadFull(body, payload); err != nil {
			return nil, nil, err
		}
		prefix.Write(payload)
		commandText := strings.TrimSuffix(string(payload), "\n")
		commandText, _, _ = strings.Cut(commandText, "\x00")
		fields := strings.Fields(commandText)
		if len(fields) != 3 || !validGitOID(fields[0]) || !validGitOID(fields[1]) || !strings.HasPrefix(fields[2], "refs/") {
			return nil, nil, errors.New("invalid receive-pack ref command")
		}
		commands = append(commands, gitRefCommand{newOID: fields[1], ref: fields[2]})
	}
	return nil, nil, errors.New("too many receive-pack ref commands")
}

func validGitOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func authorizeGitRef(command gitRefCommand, defaultBranch string, policy GitPolicy) bool {
	if strings.Trim(command.newOID, "0") == "" {
		return false
	}
	if strings.HasPrefix(command.ref, "refs/tags/") {
		return policy.Tags
	}
	if !strings.HasPrefix(command.ref, "refs/heads/") {
		return false
	}
	branch := strings.TrimPrefix(command.ref, "refs/heads/")
	switch policy.Push {
	case GitPushAll:
		return true
	case GitPushNonDefault:
		return branch != defaultBranch
	default:
		return false
	}
}

func gitCanPush(policy GitPolicy) bool {
	return policy.Push == GitPushNonDefault || policy.Push == GitPushAll || policy.Tags
}

type lfsPolicyError struct{ message string }

func (e *lfsPolicyError) Error() string { return e.message }

func authorizeLFS(req *http.Request, remainder string, policy GitPolicy) (io.ReadCloser, error) {
	if remainder == "info/lfs/objects/batch" {
		if req.Method != http.MethodPost {
			return nil, &lfsPolicyError{message: "Git LFS batch method is not allowed"}
		}
		data, err := io.ReadAll(io.LimitReader(req.Body, maxLFSBatchBytes+1))
		if err != nil || len(data) > maxLFSBatchBytes {
			return nil, errors.New("invalid LFS batch body")
		}
		var batch struct {
			Operation string `json:"operation"`
		}
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, err
		}
		switch batch.Operation {
		case "download":
		case "upload":
			if !gitCanPush(policy) {
				return nil, &lfsPolicyError{message: "Git LFS upload is not allowed"}
			}
		default:
			return nil, errors.New("unsupported LFS operation")
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	if strings.Contains(remainder, "/locks") {
		if req.Method == http.MethodGet {
			return req.Body, nil
		}
		if !gitCanPush(policy) || req.Method == http.MethodDelete {
			return nil, &lfsPolicyError{message: "Git LFS lock operation is not allowed"}
		}
		return req.Body, nil
	}
	if req.Method == http.MethodGet {
		return req.Body, nil
	}
	if req.Method == http.MethodPut && gitCanPush(policy) {
		return req.Body, nil
	}
	return nil, &lfsPolicyError{message: fmt.Sprintf("Git LFS %s is not allowed", req.Method)}
}
