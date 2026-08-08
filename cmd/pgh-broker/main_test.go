package main

import (
	"encoding/base64"
	"strings"
	"testing"

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

func TestParseKeyringRejectsMalformedKeys(t *testing.T) {
	for _, value := range []string{"", "missing-separator", "primary:not-base64", "primary:" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			_, err := parseKeyring(value)
			assert.Error(t, err)
		})
	}
}
