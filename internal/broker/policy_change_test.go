package broker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyPolicyChangeGrants(t *testing.T) {
	grants := []string{
		grantActionsWrite,
		grantChecksWrite,
		grantContentsWrite,
		grantDeploymentsWrite,
		grantObjectsDelete,
		grantPullsMerge,
		grantPullsReviewDismiss,
		grantReleasesWrite,
	}
	for _, grant := range grants {
		t.Run(grant+" added", func(t *testing.T) {
			direction, err := ClassifyPolicyChange(developerPolicy(nil, GitPushNone, false), developerPolicy(map[string]bool{grant: true}, GitPushNone, false))
			require.NoError(t, err)
			require.Equal(t, PolicyChangeBroadened, direction)
		})
		t.Run(grant+" removed", func(t *testing.T) {
			direction, err := ClassifyPolicyChange(developerPolicy(map[string]bool{grant: true}, GitPushNone, false), developerPolicy(nil, GitPushNone, false))
			require.NoError(t, err)
			require.Equal(t, PolicyChangeNarrowed, direction)
		})
	}
}

func TestClassifyPolicyChangeGitPush(t *testing.T) {
	tests := []struct {
		name   string
		before string
		after  string
		want   PolicyChangeDirection
	}{
		{name: "none to non-default", before: GitPushNone, after: GitPushNonDefault, want: PolicyChangeBroadened},
		{name: "none to all", before: GitPushNone, after: GitPushAll, want: PolicyChangeBroadened},
		{name: "non-default to all", before: GitPushNonDefault, after: GitPushAll, want: PolicyChangeBroadened},
		{name: "all to non-default", before: GitPushAll, after: GitPushNonDefault, want: PolicyChangeNarrowed},
		{name: "all to none", before: GitPushAll, after: GitPushNone, want: PolicyChangeNarrowed},
		{name: "non-default to none", before: GitPushNonDefault, after: GitPushNone, want: PolicyChangeNarrowed},
		{name: "unchanged", before: GitPushNonDefault, after: GitPushNonDefault, want: PolicyChangeUnchanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			direction, err := ClassifyPolicyChange(developerPolicy(nil, tt.before, false), developerPolicy(nil, tt.after, false))
			require.NoError(t, err)
			require.Equal(t, tt.want, direction)
		})
	}
}

func TestClassifyPolicyChangeTags(t *testing.T) {
	tests := []struct {
		name   string
		before bool
		after  bool
		want   PolicyChangeDirection
	}{
		{name: "enabled", before: false, after: true, want: PolicyChangeBroadened},
		{name: "disabled", before: true, after: false, want: PolicyChangeNarrowed},
		{name: "unchanged disabled", before: false, after: false, want: PolicyChangeUnchanged},
		{name: "unchanged enabled", before: true, after: true, want: PolicyChangeUnchanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			direction, err := ClassifyPolicyChange(developerPolicy(nil, GitPushNone, tt.before), developerPolicy(nil, GitPushNone, tt.after))
			require.NoError(t, err)
			require.Equal(t, tt.want, direction)
		})
	}
}

func TestClassifyPolicyChangeCombined(t *testing.T) {
	tests := []struct {
		name   string
		before Policy
		after  Policy
		want   PolicyChangeDirection
	}{
		{
			name:   "all dimensions broaden",
			before: developerPolicy(nil, GitPushNone, false),
			after:  developerPolicy(map[string]bool{grantActionsWrite: true}, GitPushAll, true),
			want:   PolicyChangeBroadened,
		},
		{
			name:   "all dimensions narrow",
			before: developerPolicy(map[string]bool{grantActionsWrite: true}, GitPushAll, true),
			after:  developerPolicy(nil, GitPushNone, false),
			want:   PolicyChangeNarrowed,
		},
		{
			name:   "grant exchange is mixed",
			before: developerPolicy(map[string]bool{grantActionsWrite: true}, GitPushNone, false),
			after:  developerPolicy(map[string]bool{grantChecksWrite: true}, GitPushNone, false),
			want:   PolicyChangeMixed,
		},
		{
			name:   "grant removal and Git broadening is mixed",
			before: developerPolicy(map[string]bool{grantActionsWrite: true}, GitPushNone, false),
			after:  developerPolicy(nil, GitPushAll, false),
			want:   PolicyChangeMixed,
		},
		{
			name:   "Git narrowing and tags enabling is mixed",
			before: developerPolicy(nil, GitPushAll, false),
			after:  developerPolicy(nil, GitPushNone, true),
			want:   PolicyChangeMixed,
		},
		{
			name:   "nil and empty grants are unchanged",
			before: developerPolicy(nil, GitPushNone, false),
			after:  developerPolicy(map[string]bool{}, GitPushNone, false),
			want:   PolicyChangeUnchanged,
		},
		{
			name:   "equal policies are unchanged",
			before: developerPolicy(map[string]bool{grantActionsWrite: true}, GitPushAll, true),
			after:  developerPolicy(map[string]bool{grantActionsWrite: true}, GitPushAll, true),
			want:   PolicyChangeUnchanged,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			direction, err := ClassifyPolicyChange(tt.before, tt.after)
			require.NoError(t, err)
			require.Equal(t, tt.want, direction)
		})
	}
}

func TestClassifyPolicyChangeRejectsInvalidPolicies(t *testing.T) {
	valid := developerPolicy(nil, GitPushNone, false)
	tests := []struct {
		name       string
		before     Policy
		after      Policy
		wantErrMsg string
	}{
		{name: "invalid existing profile", before: Policy{Name: "future", Version: 1, Git: GitPolicy{Push: GitPushNone}}, after: valid, wantErrMsg: "validate existing policy"},
		{name: "invalid existing push", before: developerPolicy(nil, "sometimes", false), after: valid, wantErrMsg: "validate existing policy"},
		{name: "invalid replacement grant", before: valid, after: developerPolicy(map[string]bool{"future.write": true}, GitPushNone, false), wantErrMsg: "validate replacement policy"},
		{name: "disabled replacement grant", before: valid, after: developerPolicy(map[string]bool{grantActionsWrite: false}, GitPushNone, false), wantErrMsg: "validate replacement policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			direction, err := ClassifyPolicyChange(tt.before, tt.after)
			require.ErrorContains(t, err, tt.wantErrMsg)
			require.Empty(t, direction)
		})
	}
}

func developerPolicy(grants map[string]bool, push string, tags bool) Policy {
	return Policy{
		Name:    "developer",
		Version: 1,
		Grants:  grants,
		Git:     GitPolicy{Push: push, Tags: tags},
	}
}
