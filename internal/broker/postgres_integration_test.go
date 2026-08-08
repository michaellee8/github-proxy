package broker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/cli/cli/v2/internal/brokeradmin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresAdminToBrokerCapabilityLifecycle(t *testing.T) {
	databaseURL := os.Getenv("PGH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PGH_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, broker.Migrate(ctx, pool))
	_, err = pool.Exec(ctx, `TRUNCATE pgh_capabilities, pgh_repositories, pgh_credentials CASCADE`)
	require.NoError(t, err)

	key, err := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	require.NoError(t, err)
	cipher, err := broker.NewCredentialCipher("primary", map[string][]byte{"primary": key}, rand.Reader)
	require.NoError(t, err)
	store := broker.NewPostgresStore(pool)
	service := brokeradmin.NewAdminService(store, cipher, rand.Reader, time.Now)

	credential := brokeradmin.NewCommand(service, strings.NewReader("github-upstream-token\n"), &bytes.Buffer{}, &bytes.Buffer{})
	credential.SetArgs([]string{"credential", "put", "--name", "work", "--host", "github.com"})
	require.NoError(t, credential.Execute())

	stdout := &bytes.Buffer{}
	issue := brokeradmin.NewCommand(service, &bytes.Buffer{}, stdout, &bytes.Buffer{})
	issue.SetArgs([]string{
		"capability", "issue", "--credential", "work", "--repo", "michaellee8/github-proxy",
		"--repository-id", "1326468465", "--default-branch", "main", "--git-push", "non-default",
	})
	require.NoError(t, issue.Execute())
	token := strings.TrimSpace(stdout.String())
	require.True(t, strings.HasPrefix(token, "pgh_pat_"))

	authority := broker.NewCapabilityAuthority(store, cipher, time.Now)
	handler := broker.NewHandler(broker.HandlerOptions{Authority: authority})
	req := httptest.NewRequest(http.MethodGet, "/_pgh/v1/context", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), `"owner":"michaellee8"`)
	assert.NotContains(t, res.Body.String(), "github-upstream-token")
}
