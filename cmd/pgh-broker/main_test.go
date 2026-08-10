package main

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeyringAcceptsRotationSet(t *testing.T) {
	primary := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	old := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyzABCDEF"))

	keys, err := parseKeyring("primary:" + primary + ",old:" + old)

	require.NoError(t, err)
	assert.Equal(t, []byte("01234567890123456789012345678901"), keys["primary"])
	assert.Equal(t, []byte("abcdefghijklmnopqrstuvwxyzABCDEF"), keys["old"])
}

func TestDatabaseURLDefaultsToVerifyFull(t *testing.T) {
	value, err := databaseURLWithTLS("postgres://broker:secret@db.example/pgh", false)
	require.NoError(t, err)
	parsed, err := url.Parse(value)
	require.NoError(t, err)
	assert.Equal(t, "verify-full", parsed.Query().Get("sslmode"))
}

func TestDatabaseURLRequiresExplicitInsecureDevelopmentOverride(t *testing.T) {
	_, err := databaseURLWithTLS("postgres://broker:secret@localhost/pgh?sslmode=disable", false)
	require.Error(t, err)

	value, err := databaseURLWithTLS("postgres://broker:secret@localhost/pgh?sslmode=disable", true)
	require.NoError(t, err)
	assert.Contains(t, value, "sslmode=disable")
}

func TestRepositoryCacheTTLDefaultsAndCaps(t *testing.T) {
	ttl, err := repositoryCacheTTL("")
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, ttl)

	ttl, err = repositoryCacheTTL("30m")
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, ttl)

	_, err = repositoryCacheTTL("0s")
	require.Error(t, err)
}

func TestParseKeyringRejectsMalformedKeys(t *testing.T) {
	for _, value := range []string{"", "missing-separator", "primary:not-base64", "primary:" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			_, err := parseKeyring(value)
			require.Error(t, err)
		})
	}
}
