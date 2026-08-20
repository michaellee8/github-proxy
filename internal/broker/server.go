package broker

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const protocolVersion = "1"

// HandlerOptions contains the dependencies accepted by the Broker HTTP module.
type HandlerOptions struct {
	Authority Authority
	Transport http.RoundTripper
	Auditor   RequestAuditor
	Limiter   RequestLimiter
	Now       func() time.Time
}

// NewHandler returns the complete public Broker HTTP interface.
func NewHandler(opts HandlerOptions) http.Handler {
	transport := opts.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &handler{authority: opts.Authority, transport: transport, auditor: opts.Auditor, limiter: opts.Limiter, now: now}
}

type handler struct {
	authority Authority
	transport http.RoundTripper
	auditor   RequestAuditor
	limiter   RequestLimiter
	now       func() time.Time
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
	if h.limiter == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Message: "request limiter is unavailable", Code: "PGH_UNAVAILABLE"})
		return
	}
	if h.authority == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{
			Message: "capability authority is unavailable",
			Code:    "PGH_UNAVAILABLE",
		})
		return
	}
	if h.auditor == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Message: "request audit is unavailable", Code: "PGH_AUDIT_UNAVAILABLE"})
		return
	}
	authRelease, err := h.limiter.AcquireAuthentication(req.Context())
	if err != nil {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Message: "authentication request limit exceeded", Code: "PGH_RATE_LIMITED"})
		return
	}
	class := classifyRequest(req)
	session, err := h.authority.Resolve(req.Context(), token, repositoryFreshness(class))
	authRelease()
	if err != nil {
		if errors.Is(err, ErrRepositoryIdentity) {
			writeJSON(w, http.StatusServiceUnavailable, errorResponse{
				Message: "target repository identity could not be verified",
				Code:    "PGH_REPOSITORY_UNAVAILABLE",
			})
			return
		}
		release, limitErr := h.limiter.Acquire(req.Context(), "invalid", class)
		if limitErr != nil {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, errorResponse{Message: "invalid capability request limit exceeded", Code: "PGH_RATE_LIMITED"})
			return
		}
		release()
		writeJSON(w, http.StatusUnauthorized, errorResponse{
			Message: "invalid, expired, or revoked capability token",
			Code:    "PGH_AUTH_INVALID",
		})
		return
	}
	release, err := h.limiter.Acquire(req.Context(), session.CapabilityID, class)
	if err != nil {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Message: "capability request limit exceeded", Code: "PGH_RATE_LIMITED"})
		return
	}
	defer release()
	started := h.now()
	event := AuditEvent{
		OccurredAt: started, RequestID: newAuditRequestID(), CapabilityID: session.CapabilityID,
		PolicyRevision: session.PolicyRevision, RepositoryID: session.Repository.ID,
		Method: req.Method, Path: req.URL.Path, Mutation: class == RequestMutation,
	}
	if err := h.auditor.Preflight(req.Context(), event); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{Message: "request audit is unavailable", Code: "PGH_AUDIT_UNAVAILABLE"})
		return
	}
	observed := &statusObserver{ResponseWriter: w}
	defer func() {
		event.OccurredAt = h.now()
		event.Status = observed.statusCode()
		event.DurationMS = h.now().Sub(started).Milliseconds()
		h.auditor.Result(req.Context(), event)
	}()

	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/_pgh/v1/context":
		h.serveContext(observed, session)
	case req.URL.Path == "/api/graphql":
		h.serveGraphQL(observed, req, session)
	case strings.HasPrefix(req.URL.Path, "/api/v3/"):
		h.serveREST(observed, req, session)
	case strings.Contains(req.URL.Path, ".git/"):
		h.serveGit(observed, req, session)
	default:
		writeJSON(observed, http.StatusNotFound, errorResponse{Message: "operation is not registered", Code: "PGH_OPERATION_UNKNOWN"})
	}
}

func classifyRequest(req *http.Request) RequestClass {
	if strings.HasPrefix(req.URL.Path, "/api/v3/") && req.Method != http.MethodGet && req.Method != http.MethodHead {
		return RequestMutation
	}
	if strings.Contains(req.URL.Path, ".git/") {
		if strings.HasSuffix(req.URL.Path, "/git-receive-pack") {
			return RequestMutation
		}
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/info/lfs/objects/batch") {
			return classifyLFSBatch(req)
		}
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/info/lfs/locks/verify") {
			return RequestRead
		}
		if strings.Contains(req.URL.Path, "/info/lfs/") && req.Method != http.MethodGet && req.Method != http.MethodHead {
			return RequestMutation
		}
	}
	return RequestRead
}

func classifyLFSBatch(req *http.Request) RequestClass {
	if req.Body == nil || req.Body == http.NoBody {
		return RequestMutation
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, maxLFSBatchBytes+1))
	req.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil || len(data) > maxLFSBatchBytes {
		return RequestMutation
	}
	var batch struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(data, &batch) == nil && batch.Operation == "download" {
		return RequestRead
	}
	return RequestMutation
}

func repositoryFreshness(class RequestClass) RepositoryFreshness {
	if class == RequestMutation {
		return RequireFreshRepository
	}
	return AllowCachedRepository
}

type statusObserver struct {
	http.ResponseWriter
	status int
}

func (w *statusObserver) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusObserver) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *statusObserver) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func newAuditRequestID() string {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "unavailable"
	}
	return base64.RawURLEncoding.EncodeToString(value)
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
		Name     string    `json:"name"`
		Version  int       `json:"version"`
		Revision int64     `json:"revision"`
		Grants   []string  `json:"grants"`
		Git      GitPolicy `json:"git"`
	}
	grants := make([]string, 0, len(session.Policy.Grants))
	for grant := range session.Policy.Grants {
		grants = append(grants, grant)
	}
	sort.Strings(grants)
	writeJSON(w, http.StatusOK, struct {
		CapabilityID    string             `json:"capability_id"`
		UpstreamHost    string             `json:"upstream_host"`
		Repository      repositoryResponse `json:"repository"`
		Policy          policyResponse     `json:"policy"`
		ExpiresAt       any                `json:"expires_at"`
		ProtocolVersion string             `json:"protocol_version"`
	}{
		CapabilityID: session.CapabilityID,
		UpstreamHost: session.Upstream.Host,
		Repository:   repositoryResponse{ID: session.Repository.ID, Owner: session.Repository.Owner, Name: session.Repository.Name},
		Policy: policyResponse{
			Name: session.Policy.Name, Version: session.Policy.Version, Revision: session.PolicyRevision,
			Grants: grants, Git: session.Policy.Git,
		},
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

	base, err := url.Parse(session.Upstream.APIBaseURL)
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
	upstream.Header.Set("Authorization", "Bearer "+session.Upstream.Token)
	upstream.Header.Set("X-GitHub-Api-Version", session.Upstream.APIVersion)

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
