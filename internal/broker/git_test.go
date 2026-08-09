package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrokerScopesGitUploadPackWithBasicCapabilityAuth(t *testing.T) {
	var upstream *http.Request
	handler := NewHandler(HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstream = req.Clone(req.Context())
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("001e# service=git-upload-pack\n0000"))}, nil
		}),
	})
	req := httptest.NewRequest(http.MethodGet, "/michaellee8/github-proxy.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:pgh_pat_selector_secret")))
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NotNil(t, upstream)
	assert.Equal(t, "https://github.com/michaellee8/github-proxy.git/info/refs?service=git-upload-pack", upstream.URL.String())
	username, password, ok := upstream.BasicAuth()
	assert.True(t, ok)
	assert.Equal(t, "x-access-token", username)
	assert.Equal(t, "upstream-secret", password)
}

func TestBrokerEnforcesReceivePackRefPolicy(t *testing.T) {
	const oldOID = "1111111111111111111111111111111111111111"
	const newOID = "2222222222222222222222222222222222222222"
	const zeroOID = "0000000000000000000000000000000000000000"
	tests := []struct {
		name       string
		ref        string
		newOID     string
		git        GitPolicy
		wantStatus int
		wantCall   bool
	}{
		{name: "non-default branch", ref: "refs/heads/agent-work", newOID: newOID, git: GitPolicy{Push: GitPushNonDefault}, wantStatus: http.StatusOK, wantCall: true},
		{name: "default branch denied", ref: "refs/heads/main", newOID: newOID, git: GitPolicy{Push: GitPushNonDefault}, wantStatus: http.StatusForbidden},
		{name: "default branch granted", ref: "refs/heads/main", newOID: newOID, git: GitPolicy{Push: GitPushAll}, wantStatus: http.StatusOK, wantCall: true},
		{name: "deletion always denied", ref: "refs/heads/agent-work", newOID: zeroOID, git: GitPolicy{Push: GitPushAll, Tags: true}, wantStatus: http.StatusForbidden},
		{name: "tag needs grant", ref: "refs/tags/v1", newOID: newOID, git: GitPolicy{Push: GitPushAll}, wantStatus: http.StatusForbidden},
		{name: "tag granted", ref: "refs/tags/v1", newOID: newOID, git: GitPolicy{Push: GitPushAll, Tags: true}, wantStatus: http.StatusOK, wantCall: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := oldOID + " " + tt.newOID + " " + tt.ref + "\x00report-status\n"
			body := append(pktLine(command), []byte("0000PACKpayload")...)
			var gotBody []byte
			called := false
			policy := Policy{Name: "developer", Version: 1, Git: tt.git}
			handler := NewHandler(HandlerOptions{
				Authority: authorityWithPolicy(t, policy),
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					called = true
					var err error
					gotBody, err = io.ReadAll(req.Body)
					require.NoError(t, err)
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("0000"))}, nil
				}),
			})
			req := httptest.NewRequest(http.MethodPost, "/michaellee8/github-proxy.git/git-receive-pack", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
			res := httptest.NewRecorder()

			handler.ServeHTTP(res, req)

			require.Equal(t, tt.wantStatus, res.Code)
			assert.Equal(t, tt.wantCall, called)
			if called {
				assert.Equal(t, body, gotBody)
			}
		})
	}
}

func TestBrokerAcceptsShallowReceivePackPreamble(t *testing.T) {
	const oldOID = "1111111111111111111111111111111111111111"
	const newOID = "2222222222222222222222222222222222222222"
	command := oldOID + " " + newOID + " refs/tags/v1\x00report-status\n"
	body := append(pktLine("shallow "+oldOID+"\n"), pktLine(command)...)
	body = append(body, []byte("0000PACKpayload")...)
	called := false
	handler := NewHandler(HandlerOptions{
		Authority: authorityWithPolicy(t, Policy{Name: "developer", Version: 1, Git: GitPolicy{Tags: true}}),
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			forwarded, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, body, forwarded)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("0000"))}, nil
		}),
	})
	req := httptest.NewRequest(http.MethodPost, "/michaellee8/github-proxy.git/git-receive-pack", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	assert.True(t, called)
}

func TestBrokerScopesLFSBatchOperations(t *testing.T) {
	for _, tt := range []struct {
		operation  string
		git        GitPolicy
		wantStatus int
		wantCall   bool
	}{
		{operation: "download", wantStatus: http.StatusOK, wantCall: true},
		{operation: "upload", wantStatus: http.StatusForbidden},
		{operation: "upload", git: GitPolicy{Push: GitPushNonDefault}, wantStatus: http.StatusOK, wantCall: true},
	} {
		t.Run(fmt.Sprintf("%s-%d", tt.operation, tt.wantStatus), func(t *testing.T) {
			called := false
			handler := NewHandler(HandlerOptions{
				Authority: authorityWithPolicy(t, Policy{Name: "developer", Version: 1, Git: tt.git}),
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					called = true
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"objects":[]}`))}, nil
				}),
			})
			payload, err := json.Marshal(map[string]any{"operation": tt.operation, "objects": []any{map[string]any{"oid": strings.Repeat("a", 64), "size": 1}}})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/michaellee8/github-proxy.git/info/lfs/objects/batch", bytes.NewReader(payload))
			req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
			res := httptest.NewRecorder()

			handler.ServeHTTP(res, req)

			require.Equal(t, tt.wantStatus, res.Code)
			assert.Equal(t, tt.wantCall, called)
		})
	}
}

func pktLine(payload string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(payload)+4, payload))
}
