package broker

import (
	"context"
	"time"
)

// Authority resolves an opaque capability into the complete trusted session
// needed to authorize and execute one request.
type Authority interface {
	Resolve(context.Context, string) (Session, error)
}

// Session is the trusted request context returned by an Authority.
type Session struct {
	CapabilityID string
	Repository   Repository
	Policy       Policy
	ExpiresAt    *time.Time
}

// Repository identifies the only upstream repository available to a Session.
type Repository struct {
	ID            int64
	Owner         string
	Name          string
	UpstreamHost  string
	APIBaseURL    string
	APIVersion    string
	UpstreamToken string
	DefaultBranch string
}

// Policy identifies the resolved authorization profile for a Session.
type Policy struct {
	Name    string
	Version int
	Grants  map[string]bool
	Git     GitPolicy
}

const (
	GitPushNone       = "none"
	GitPushNonDefault = "non-default"
	GitPushAll        = "all"
)

// GitPolicy grants ref-level authority for Git smart HTTP.
type GitPolicy struct {
	Push string
	Tags bool
}
