package broker

import (
	"context"
	"time"
)

// Authority resolves an opaque capability into the complete trusted session
// needed to authorize and execute one request.
type Authority interface {
	Resolve(context.Context, string, RepositoryFreshness) (Session, error)
}

// RepositoryFreshness controls whether a cached Repository Observation may be used.
type RepositoryFreshness bool

const (
	// AllowCachedRepository permits a current cached observation for read operations.
	AllowCachedRepository RepositoryFreshness = false
	// RequireFreshRepository revalidates identity before a mutation.
	RequireFreshRepository RepositoryFreshness = true
)

// Session is the trusted request context returned by an Authority.
type Session struct {
	CapabilityID   string
	PolicyRevision int64
	Repository     Repository
	Upstream       UpstreamAccess
	Policy         Policy
	ExpiresAt      *time.Time
}

// Repository identifies the only upstream repository available to a Session.
type Repository struct {
	ID            int64
	Owner         string
	Name          string
	DefaultBranch string
	ETag          string
	ValidatedAt   time.Time
}

// RepositoryRequest identifies a repository by its operator-facing name and an
// optional immutable identity assertion.
type RepositoryRequest struct {
	Owner      string
	Name       string
	ExpectedID *int64
}

const (
	// RepositoryResolutionNumeric resolves mutable metadata from an immutable ID.
	RepositoryResolutionNumeric = "numeric-id"
	// RepositoryResolutionName resolves metadata through the documented owner/name route.
	RepositoryResolutionName = "owner-name"
)

// UpstreamAccess contains request-time GitHub access material for one credential.
type UpstreamAccess struct {
	CredentialID         string
	Host                 string
	APIBaseURL           string
	APIVersion           string
	RepositoryResolution string
	Token                string
}

// Policy identifies the resolved authorization profile for a Session.
type Policy struct {
	Name    string          `json:"name"`
	Version int             `json:"version"`
	Grants  map[string]bool `json:"grants"`
	Git     GitPolicy       `json:"git"`
}

const (
	// GitPushNone denies all branch updates.
	GitPushNone = "none"
	// GitPushNonDefault permits branch updates except to the bound default branch.
	GitPushNonDefault = "non-default"
	// GitPushAll permits updates to every branch in the bound repository.
	GitPushAll = "all"
)

// GitPolicy grants ref-level authority for Git smart HTTP.
type GitPolicy struct {
	Push string `json:"push"`
	Tags bool   `json:"tags"`
}
