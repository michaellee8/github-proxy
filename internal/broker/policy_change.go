package broker

import "fmt"

// PolicyChangeDirection describes how a replacement changes effective authority.
type PolicyChangeDirection string

const (
	// PolicyChangeUnchanged indicates that both policies grant the same authority.
	PolicyChangeUnchanged PolicyChangeDirection = "unchanged"
	// PolicyChangeBroadened indicates that authority was added without removing any.
	PolicyChangeBroadened PolicyChangeDirection = "broadened"
	// PolicyChangeNarrowed indicates that authority was removed without adding any.
	PolicyChangeNarrowed PolicyChangeDirection = "narrowed"
	// PolicyChangeMixed indicates that authority was both added and removed.
	PolicyChangeMixed PolicyChangeDirection = "mixed"
)

// ClassifyPolicyChange compares the effective authority of two supported Policy Profiles.
func ClassifyPolicyChange(before, after Policy) (PolicyChangeDirection, error) {
	if err := ValidatePolicy(before); err != nil {
		return "", fmt.Errorf("validate existing policy: %w", err)
	}
	if err := ValidatePolicy(after); err != nil {
		return "", fmt.Errorf("validate replacement policy: %w", err)
	}

	var gained, lost bool
	for grant := range before.Grants {
		if !after.allows(grant) {
			lost = true
		}
	}
	for grant := range after.Grants {
		if !before.allows(grant) {
			gained = true
		}
	}

	beforePush := gitPushAuthority(before.Git.Push)
	afterPush := gitPushAuthority(after.Git.Push)
	if afterPush > beforePush {
		gained = true
	} else if afterPush < beforePush {
		lost = true
	}
	if after.Git.Tags && !before.Git.Tags {
		gained = true
	} else if before.Git.Tags && !after.Git.Tags {
		lost = true
	}

	switch {
	case gained && lost:
		return PolicyChangeMixed, nil
	case gained:
		return PolicyChangeBroadened, nil
	case lost:
		return PolicyChangeNarrowed, nil
	default:
		return PolicyChangeUnchanged, nil
	}
}

func gitPushAuthority(mode string) int {
	switch mode {
	case GitPushNone:
		return 0
	case GitPushNonDefault:
		return 1
	case GitPushAll:
		return 2
	default:
		panic("gitPushAuthority called with an invalid mode")
	}
}
