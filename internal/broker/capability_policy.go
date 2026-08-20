package broker

import (
	"sort"
	"time"
)

const (
	// CapabilityStateActive identifies a usable capability.
	CapabilityStateActive = "active"
	// CapabilityStateExpired identifies a capability past its configured lifetime.
	CapabilityStateExpired = "expired"
	// CapabilityStateRevoked identifies a permanently disabled capability.
	CapabilityStateRevoked = "revoked"
)

// PolicyRepresentation is the stable administrative and Agent Host view of a Policy Profile assignment.
type PolicyRepresentation struct {
	Name     string    `json:"name"`
	Version  int       `json:"version"`
	Revision int64     `json:"revision"`
	Grants   []string  `json:"grants"`
	Git      GitPolicy `json:"git"`
}

// NewPolicyRepresentation returns a deterministic representation of a Policy Profile assignment.
func NewPolicyRepresentation(policy Policy, revision int64) PolicyRepresentation {
	grants := make([]string, 0, len(policy.Grants))
	for grant := range policy.Grants {
		grants = append(grants, grant)
	}
	sort.Strings(grants)
	return PolicyRepresentation{
		Name: policy.Name, Version: policy.Version, Revision: revision, Grants: grants, Git: policy.Git,
	}
}

// Policy reconstructs the authorization policy represented by this value.
func (p PolicyRepresentation) Policy() Policy {
	grants := make(map[string]bool, len(p.Grants))
	for _, grant := range p.Grants {
		grants[grant] = true
	}
	return Policy{Name: p.Name, Version: p.Version, Grants: grants, Git: p.Git}
}

// CapabilityRepository identifies the immutable Target Repository in administrative output.
type CapabilityRepository struct {
	ID    int64  `json:"id"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// CapabilityPolicyView describes the current policy and lifecycle state of one Repository Capability.
type CapabilityPolicyView struct {
	CapabilityID    string               `json:"capability_id"`
	State           string               `json:"state"`
	Repository      CapabilityRepository `json:"repository"`
	Policy          PolicyRepresentation `json:"policy"`
	ExpiresAt       *time.Time           `json:"expires_at"`
	RevokedAt       *time.Time           `json:"revoked_at"`
	CreatedAt       time.Time            `json:"created_at"`
	PolicyUpdatedAt time.Time            `json:"policy_updated_at"`
}

// CapabilityPolicyReplacement contains one complete requested policy replacement.
type CapabilityPolicyReplacement struct {
	CapabilityID string
	Policy       Policy
	Reason       string
	Actor        string
}

// CapabilityPolicyReplacementResult reports whether a replacement changed authority.
type CapabilityPolicyReplacementResult struct {
	Changed    bool                 `json:"changed"`
	Capability CapabilityPolicyView `json:"capability"`
}

// CapabilityPolicyEvent is one permanent administrative policy-change record.
type CapabilityPolicyEvent struct {
	OccurredAt     time.Time             `json:"time"`
	Event          string                `json:"event"`
	CapabilityID   string                `json:"capability_id"`
	RepositoryID   int64                 `json:"repository_id"`
	BeforeRevision int64                 `json:"before_revision"`
	AfterRevision  int64                 `json:"after_revision"`
	Before         PolicyRepresentation  `json:"before"`
	After          PolicyRepresentation  `json:"after"`
	Direction      PolicyChangeDirection `json:"direction"`
	Reason         string                `json:"reason"`
	Actor          string                `json:"actor,omitempty"`
}

// CapabilityPolicyHistoryQuery bounds one capability's permanent policy history.
type CapabilityPolicyHistoryQuery struct {
	CapabilityID string
	Since        *time.Time
	Limit        int
}

func capabilityState(expiresAt, revokedAt *time.Time, now time.Time) string {
	if revokedAt != nil {
		return CapabilityStateRevoked
	}
	if expiresAt != nil && !expiresAt.After(now) {
		return CapabilityStateExpired
	}
	return CapabilityStateActive
}
