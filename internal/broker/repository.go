package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	defaultRepositoryObservationTTL = 30 * time.Second
	maxRepositoryObservationTTL     = 5 * time.Minute
	maxRepositoryMetadataBytes      = 1 << 20
)

var ErrRepositoryIdentity = errors.New("repository identity could not be verified")

type repositoryCacheEntry struct {
	repository Repository
	expiresAt  time.Time
}

// RepositoryResolver verifies immutable repository identity and owns mutable
// Repository Observation caching.
type RepositoryResolver struct {
	transport http.RoundTripper
	now       func() time.Time
	ttl       time.Duration
	mu        sync.RWMutex
	cache     map[string]repositoryCacheEntry
	group     singleflight.Group
}

// NewRepositoryResolver constructs a fail-closed GitHub repository resolver.
func NewRepositoryResolver(transport http.RoundTripper, now func() time.Time, ttl time.Duration) *RepositoryResolver {
	if transport == nil {
		transport = http.DefaultTransport
	}
	if now == nil {
		now = time.Now
	}
	ttl = NormalizeRepositoryObservationTTL(ttl)
	return &RepositoryResolver{transport: transport, now: now, ttl: ttl, cache: make(map[string]repositoryCacheEntry)}
}

// NormalizeRepositoryObservationTTL applies the documented default and maximum
// lifetime for a successful read observation.
func NormalizeRepositoryObservationTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return defaultRepositoryObservationTTL
	}
	if ttl > maxRepositoryObservationTTL {
		return maxRepositoryObservationTTL
	}
	return ttl
}

// ResolveByName verifies an operator-supplied repository name during issuance.
func (r *RepositoryResolver) ResolveByName(ctx context.Context, upstream UpstreamAccess, requested RepositoryRequest) (Repository, error) {
	if r == nil || requested.Owner == "" || requested.Name == "" {
		return Repository{}, ErrRepositoryIdentity
	}
	endpoint, err := repositoryNameURL(upstream.APIBaseURL, requested.Owner, requested.Name)
	if err != nil {
		return Repository{}, ErrRepositoryIdentity
	}
	repository, err := r.fetch(ctx, upstream, endpoint, Repository{})
	if err != nil {
		return Repository{}, err
	}
	if requested.ExpectedID != nil && repository.ID != *requested.ExpectedID {
		return Repository{}, ErrRepositoryIdentity
	}
	r.storeCache(upstream.CredentialID, repository)
	return repository, nil
}

// Resolve returns a verified current observation for a Target Repository.
func (r *RepositoryResolver) Resolve(ctx context.Context, upstream UpstreamAccess, target Repository, freshness RepositoryFreshness) (Repository, error) {
	if r == nil || target.ID <= 0 || upstream.CredentialID == "" {
		return Repository{}, ErrRepositoryIdentity
	}
	key := repositoryCacheKey(upstream.CredentialID, target.ID)
	if freshness == AllowCachedRepository {
		if cached, ok := r.cached(key); ok {
			return cached, nil
		}
		if !target.ValidatedAt.IsZero() && r.now().Before(target.ValidatedAt.Add(r.ttl)) {
			r.storeCache(upstream.CredentialID, target)
			return target, nil
		}
	} else {
		return r.resolveCurrent(ctx, upstream, target, key)
	}

	value, err, _ := r.group.Do(key, func() (any, error) {
		if cached, ok := r.cached(key); ok {
			return cached, nil
		}
		return r.resolveCurrent(ctx, upstream, target, key)
	})
	if err != nil {
		return Repository{}, err
	}
	return value.(Repository), nil
}

func (r *RepositoryResolver) resolveCurrent(ctx context.Context, upstream UpstreamAccess, target Repository, key string) (Repository, error) {
	cached := target
	if entry, ok := r.cacheEntry(key); ok {
		cached = entry.repository
	}
	var endpoint *url.URL
	var err error
	switch upstream.RepositoryResolution {
	case RepositoryResolutionNumeric:
		endpoint, err = repositoryNumericURL(upstream.APIBaseURL, target.ID)
	case RepositoryResolutionName:
		endpoint, err = repositoryNameURL(upstream.APIBaseURL, target.Owner, target.Name)
	default:
		return Repository{}, ErrRepositoryIdentity
	}
	if err != nil {
		return Repository{}, ErrRepositoryIdentity
	}
	repository, err := r.fetch(ctx, upstream, endpoint, cached)
	if err != nil || repository.ID != target.ID {
		return Repository{}, ErrRepositoryIdentity
	}
	r.storeCache(upstream.CredentialID, repository)
	return repository, nil
}

func (r *RepositoryResolver) fetch(ctx context.Context, upstream UpstreamAccess, endpoint *url.URL, cached Repository) (Repository, error) {
	current := endpoint
	var response *http.Response
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return Repository{}, ErrRepositoryIdentity
		}
		req.Header.Set("Authorization", "Bearer "+upstream.Token)
		req.Header.Set("Accept", "application/vnd.github+json")
		if upstream.APIVersion != "" {
			req.Header.Set("X-GitHub-Api-Version", upstream.APIVersion)
		}
		if cached.ETag != "" {
			req.Header.Set("If-None-Match", cached.ETag)
		}
		response, err = r.transport.RoundTrip(req)
		if err != nil {
			return Repository{}, ErrRepositoryIdentity
		}
		if response.StatusCode != http.StatusMovedPermanently {
			break
		}
		location, err := response.Location()
		response.Body.Close()
		if err != nil || attempt != 0 || location.Scheme != "https" || !strings.EqualFold(location.Host, endpoint.Host) || location.User != nil || location.RawQuery != "" || location.Fragment != "" {
			return Repository{}, ErrRepositoryIdentity
		}
		current = location
	}
	if response == nil {
		return Repository{}, ErrRepositoryIdentity
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified && cached.ID > 0 {
		cached.ValidatedAt = r.now()
		return cached, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Repository{}, ErrRepositoryIdentity
	}
	var metadata struct {
		ID            int64  `json:"id"`
		Name          string `json:"name"`
		DefaultBranch string `json:"default_branch"`
		Owner         struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxRepositoryMetadataBytes+1))
	if err != nil || len(data) > maxRepositoryMetadataBytes {
		return Repository{}, ErrRepositoryIdentity
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&metadata); err != nil || ensureJSONEnd(decoder) != nil || metadata.ID <= 0 || metadata.Owner.Login == "" || metadata.Name == "" || metadata.DefaultBranch == "" {
		return Repository{}, ErrRepositoryIdentity
	}
	repository := Repository{
		ID: metadata.ID, Owner: metadata.Owner.Login, Name: metadata.Name, DefaultBranch: metadata.DefaultBranch,
		ETag: response.Header.Get("ETag"), ValidatedAt: r.now(),
	}
	return repository, nil
}

func repositoryNameURL(apiBase, owner, name string) (*url.URL, error) {
	base, err := url.Parse(apiBase)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil {
		return nil, errors.New("invalid API base URL")
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base, nil
}

func repositoryNumericURL(apiBase string, id int64) (*url.URL, error) {
	base, err := url.Parse(apiBase)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || id <= 0 {
		return nil, errors.New("invalid repository identity")
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/repositories/" + strconv.FormatInt(id, 10)
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base, nil
}

func (r *RepositoryResolver) storeCache(credentialID string, repository Repository) {
	if credentialID == "" || repository.ID <= 0 {
		return
	}
	r.mu.Lock()
	r.cache[repositoryCacheKey(credentialID, repository.ID)] = repositoryCacheEntry{repository: repository, expiresAt: r.now().Add(r.ttl)}
	r.mu.Unlock()
}

func (r *RepositoryResolver) cached(key string) (Repository, bool) {
	entry, ok := r.cacheEntry(key)
	if !ok || !r.now().Before(entry.expiresAt) {
		return Repository{}, false
	}
	return entry.repository, true
}

func (r *RepositoryResolver) cacheEntry(key string) (repositoryCacheEntry, bool) {
	r.mu.RLock()
	entry, ok := r.cache[key]
	r.mu.RUnlock()
	return entry, ok
}

func repositoryCacheKey(credentialID string, repositoryID int64) string {
	return fmt.Sprintf("%s:%d", credentialID, repositoryID)
}
