package broker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRepositoryResolverRevalidatesEveryConcurrentMutation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	resolver := NewRepositoryResolver(roundTripFunc(func(*http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-release
		return repositoryMetadataResponse(`{"id":99,"owner":{"login":"owner"},"name":"repo","default_branch":"main"}`), nil
	}), time.Now, 30*time.Second)
	access := UpstreamAccess{
		CredentialID: "cred-1", APIBaseURL: "https://api.github.com", APIVersion: "2022-11-28",
		RepositoryResolution: RepositoryResolutionNumeric, Token: "upstream",
	}
	target := Repository{ID: 99, Owner: "owner", Name: "repo", DefaultBranch: "main"}

	var wait sync.WaitGroup
	errors := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := resolver.Resolve(context.Background(), access, target, RequireFreshRepository)
			errors <- err
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(500 * time.Millisecond):
			close(release)
			wait.Wait()
			t.Fatal("concurrent mutation reused another request's repository revalidation")
		}
	}
	close(release)
	wait.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

func TestRepositoryResolverRejectsTrailingMetadata(t *testing.T) {
	resolver := NewRepositoryResolver(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return repositoryMetadataResponse(`{"id":99,"owner":{"login":"owner"},"name":"repo","default_branch":"main"}{}`), nil
	}), time.Now, 30*time.Second)

	_, err := resolver.ResolveByName(context.Background(), UpstreamAccess{
		CredentialID: "cred-1", APIBaseURL: "https://api.github.com", Token: "upstream",
	}, RepositoryRequest{Owner: "owner", Name: "repo"})

	require.ErrorIs(t, err, ErrRepositoryIdentity)
}

func repositoryMetadataResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
