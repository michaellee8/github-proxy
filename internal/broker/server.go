package broker

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const protocolVersion = "1"

// HandlerOptions contains the dependencies accepted by the Broker HTTP module.
type HandlerOptions struct {
	Authority Authority
	Transport http.RoundTripper
}

// NewHandler returns the complete public Broker HTTP interface.
func NewHandler(opts HandlerOptions) http.Handler {
	transport := opts.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &handler{authority: opts.Authority, transport: transport}
}

type handler struct {
	authority Authority
	transport http.RoundTripper
}

type errorResponse struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet && req.URL.Path == "/healthz" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	token, ok := capabilityToken(req)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Message: "missing capability token",
			Code:    "PGH_AUTH_REQUIRED",
		})
		return
	}
	if h.authority == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Message: "capability authority is unavailable",
			Code:    "PGH_UNAVAILABLE",
		})
		return
	}

	session, err := h.authority.Resolve(req.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Message: "invalid, expired, or revoked capability token",
			Code:    "PGH_AUTH_INVALID",
		})
		return
	}

	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/_pgh/v1/context":
		h.serveContext(w, session)
	case req.URL.Path == "/api/graphql":
		h.serveGraphQL(w, req, session)
	case strings.HasPrefix(req.URL.Path, "/api/v3/"):
		h.serveREST(w, req, session)
	case strings.Contains(req.URL.Path, ".git/"):
		h.serveGit(w, req, session)
	default:
		writeJSON(w, http.StatusNotFound, errorResponse{Message: "operation is not registered", Code: "PGH_OPERATION_UNKNOWN"})
	}
}

func capabilityToken(req *http.Request) (string, bool) {
	if token, ok := authorizationToken(req.Header.Get("Authorization")); ok {
		return token, true
	}
	username, password, ok := req.BasicAuth()
	if !ok || (username != "x-access-token" && username != "pgh") || password == "" {
		return "", false
	}
	return password, true
}

func (h *handler) serveContext(w http.ResponseWriter, session Session) {
	type repositoryResponse struct {
		ID    int64  `json:"id"`
		Owner string `json:"owner"`
		Name  string `json:"name"`
	}
	type policyResponse struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}
	writeJSON(w, http.StatusOK, struct {
		CapabilityID    string             `json:"capability_id"`
		UpstreamHost    string             `json:"upstream_host"`
		Repository      repositoryResponse `json:"repository"`
		Policy          policyResponse     `json:"policy"`
		ExpiresAt       any                `json:"expires_at"`
		ProtocolVersion string             `json:"protocol_version"`
	}{
		CapabilityID:    session.CapabilityID,
		UpstreamHost:    session.Repository.UpstreamHost,
		Repository:      repositoryResponse{ID: session.Repository.ID, Owner: session.Repository.Owner, Name: session.Repository.Name},
		Policy:          policyResponse{Name: session.Policy.Name, Version: session.Policy.Version},
		ExpiresAt:       session.ExpiresAt,
		ProtocolVersion: protocolVersion,
	})
}

func (h *handler) serveREST(w http.ResponseWriter, req *http.Request, session Session) {
	if !validBrokerPath(req.URL.Path, req.URL.EscapedPath()) {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "request path is invalid", Code: "PGH_PATH_INVALID"})
		return
	}
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/api/v3/"), "/")
	if len(parts) < 3 || parts[0] != "repos" {
		writeJSON(w, http.StatusForbidden, errorResponse{Message: "operation is not allowed by this capability", Code: "PGH_POLICY_DENIED"})
		return
	}
	if !strings.EqualFold(parts[1], session.Repository.Owner) || !strings.EqualFold(parts[2], session.Repository.Name) {
		writeJSON(w, http.StatusForbidden, errorResponse{Message: "repository is outside this capability", Code: "PGH_REPOSITORY_DENIED"})
		return
	}
	if !authorizeREST(req.Method, parts[3:], session.Policy) {
		writeJSON(w, http.StatusForbidden, errorResponse{Message: "operation is not allowed by this capability", Code: "PGH_POLICY_DENIED"})
		return
	}
	if status, response := authorizeRESTBody(req, parts[3:], session.Repository, session.Policy); response.Code != "" {
		writeJSON(w, status, response)
		return
	}

	base, err := url.Parse(session.Repository.APIBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Message: "upstream host is misconfigured", Code: "PGH_UPSTREAM_INVALID"})
		return
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/repos/" + session.Repository.Owner + "/" + session.Repository.Name
	if len(parts) > 3 {
		base.Path += "/" + strings.Join(parts[3:], "/")
	}
	base.RawQuery = req.URL.RawQuery

	upstream, err := http.NewRequestWithContext(req.Context(), req.Method, base.String(), req.Body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorResponse{Message: "failed to build upstream request", Code: "PGH_UPSTREAM_ERROR"})
		return
	}
	copyEndToEndHeaders(upstream.Header, req.Header)
	upstream.Header.Set("Authorization", "Bearer "+session.Repository.UpstreamToken)
	upstream.Header.Set("X-GitHub-Api-Version", session.Repository.APIVersion)

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

func authorizationToken(value string) (string, bool) {
	scheme, token, ok := strings.Cut(value, " ")
	if !ok || (!strings.EqualFold(scheme, "bearer") && !strings.EqualFold(scheme, "token")) ||
		token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func copyEndToEndHeaders(dst, src http.Header) {
	for name, values := range src {
		switch strings.ToLower(name) {
		case "authorization", "cookie", "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-github-api-version":
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
