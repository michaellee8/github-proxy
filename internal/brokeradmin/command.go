package brokeradmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/spf13/cobra"
)

// PutCredentialRequest contains an Upstream Credential read by the offline admin CLI.
type PutCredentialRequest struct {
	Name                 string
	UpstreamHost         string
	APIBaseURL           string
	APIVersion           string
	RepositoryResolution string
	Token                []byte
}

// Service is the privileged administrative boundary. It is never exposed over HTTP.
type Service interface {
	PutCredential(context.Context, PutCredentialRequest) error
	Issue(context.Context, broker.IssueRequest) (broker.IssuedCapability, error)
	Revoke(context.Context, string) error
	ShowPolicy(context.Context, string) (broker.CapabilityPolicyView, error)
	ReplacePolicy(context.Context, ReplacePolicyRequest) (broker.CapabilityPolicyReplacementResult, error)
	ListPolicyHistory(context.Context, broker.CapabilityPolicyHistoryQuery) ([]broker.CapabilityPolicyEvent, error)
	ListAuditEvents(context.Context, broker.AuditQuery) ([]broker.AuditEvent, error)
}

// CommandOptions contains the offline service, streams, and clock used by the command tree.
type CommandOptions struct {
	Service Service
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Now     func() time.Time
}

// NewCommand constructs the offline pgh-broker administrative command tree.
func NewCommand(options CommandOptions) *cobra.Command {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	root := &cobra.Command{
		Use:           "pgh-broker",
		Short:         "Administer repository-scoped GitHub capabilities",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(options.Stdin)
	root.SetOut(options.Stdout)
	root.SetErr(options.Stderr)
	root.AddCommand(newCredentialCommand(options.Service), newCapabilityCommand(options.Service, now), newAuditCommand(options.Service))
	return root
}

func newAuditCommand(service Service) *cobra.Command {
	audit := &cobra.Command{Use: "audit", Short: "Inspect redacted Broker request events"}
	audit.AddCommand(newAuditListCommand(service, nil))
	return audit
}

type auditListOptions struct {
	service      Service
	context      context.Context
	stdout       io.Writer
	capabilityID string
	repositoryID int64
	sinceValue   string
	limit        int
}

func newAuditListCommand(service Service, runF func(*auditListOptions) error) *cobra.Command {
	opts := &auditListOptions{service: service, limit: 100}
	if runF == nil {
		runF = auditListRun
	}
	command := &cobra.Command{
		Use:   "list",
		Short: "Print newest audit events as JSON lines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.context = cmd.Context()
			opts.stdout = cmd.OutOrStdout()
			return runF(opts)
		},
	}
	command.Flags().StringVar(&opts.capabilityID, "capability", "", "filter by opaque capability ID")
	command.Flags().Int64Var(&opts.repositoryID, "repository-id", 0, "filter by immutable repository ID")
	command.Flags().StringVar(&opts.sinceValue, "since", "", "filter at or after an RFC3339 timestamp")
	command.Flags().IntVar(&opts.limit, "limit", opts.limit, "maximum events to return (1-1000)")
	return command
}

func auditListRun(opts *auditListOptions) error {
	if opts.service == nil {
		return errors.New("admin service is unavailable")
	}
	if opts.capabilityID != "" && !strings.HasPrefix(opts.capabilityID, "cap_") {
		return cmdutil.FlagErrorf("capability must be an opaque cap_ ID")
	}
	if opts.repositoryID < 0 {
		return cmdutil.FlagErrorf("repository-id must be positive")
	}
	if opts.limit <= 0 || opts.limit > 1000 {
		return cmdutil.FlagErrorf("limit must be between 1 and 1000")
	}
	var since *time.Time
	if opts.sinceValue != "" {
		parsed, err := time.Parse(time.RFC3339, opts.sinceValue)
		if err != nil {
			return cmdutil.FlagErrorf("since must be an RFC3339 timestamp")
		}
		since = &parsed
	}
	events, err := opts.service.ListAuditEvents(opts.context, broker.AuditQuery{
		CapabilityID: opts.capabilityID, RepositoryID: optionalPositiveInt64(opts.repositoryID), Since: since, Limit: opts.limit,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(opts.stdout)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("write audit event: %w", err)
		}
	}
	return nil
}

func newCredentialCommand(service Service) *cobra.Command {
	credential := &cobra.Command{Use: "credential", Short: "Manage encrypted upstream credentials"}
	var request PutCredentialRequest
	put := &cobra.Command{
		Use:   "put",
		Short: "Read a GitHub PAT from stdin and store it encrypted",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if service == nil {
				return errors.New("admin service is unavailable")
			}
			if request.RepositoryResolution != broker.RepositoryResolutionNumeric && request.RepositoryResolution != broker.RepositoryResolutionName {
				return cmdutil.FlagErrorf("repository-resolution must be numeric-id or owner-name")
			}
			data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 64*1024+1))
			if err != nil {
				return fmt.Errorf("read upstream credential: %w", err)
			}
			if len(data) > 64*1024 {
				return errors.New("upstream credential exceeds 64 KiB")
			}
			request.Token = []byte(strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"))
			if len(request.Token) == 0 || strings.ContainsAny(string(request.Token), "\r\n") {
				return errors.New("stdin must contain exactly one non-empty credential")
			}
			if err := service.PutCredential(cmd.Context(), request); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored credential %s\n", request.Name)
			return nil
		},
	}
	put.Flags().StringVar(&request.Name, "name", "", "credential name")
	put.Flags().StringVar(&request.UpstreamHost, "host", "", "upstream GitHub host")
	put.Flags().StringVar(&request.APIBaseURL, "api-base-url", "https://api.github.com", "upstream REST API base URL")
	put.Flags().StringVar(&request.APIVersion, "api-version", "2022-11-28", "tested GitHub REST API version")
	put.Flags().StringVar(&request.RepositoryResolution, "repository-resolution", broker.RepositoryResolutionNumeric, "repository resolution mode: numeric-id or owner-name")
	_ = put.MarkFlagRequired("name")
	_ = put.MarkFlagRequired("host")
	credential.AddCommand(put)
	return credential
}

func newCapabilityCommand(service Service, now func() time.Time) *cobra.Command {
	capability := &cobra.Command{Use: "capability", Short: "Manage repository capabilities"}
	var credential, repo, profile, expiresIn, gitPush string
	var expectedRepositoryID int64
	var policyVersion int
	var grants []string
	var gitTags bool
	issue := &cobra.Command{
		Use:   "issue",
		Short: "Issue a one-time repository capability token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if service == nil {
				return errors.New("admin service is unavailable")
			}
			owner, name, ok := strings.Cut(repo, "/")
			if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
				return cmdutil.FlagErrorf("repo must be exactly OWNER/NAME")
			}
			if expectedRepositoryID < 0 {
				return cmdutil.FlagErrorf("expected-repository-id must be positive")
			}
			policyGrants := make(map[string]bool, len(grants))
			for _, grant := range grants {
				if !broker.IsKnownGrant(grant) {
					return cmdutil.FlagErrorf("unknown policy grant %q", grant)
				}
				policyGrants[grant] = true
			}
			if gitPush != broker.GitPushNone && gitPush != broker.GitPushNonDefault && gitPush != broker.GitPushAll {
				return cmdutil.FlagErrorf("git-push must be none, non-default, or all")
			}
			policy := broker.Policy{Name: profile, Version: policyVersion, Grants: policyGrants, Git: broker.GitPolicy{Push: gitPush, Tags: gitTags}}
			if err := broker.ValidatePolicy(policy); err != nil {
				return cmdutil.FlagErrorf("%s", err)
			}
			var expiresAt *time.Time
			if expiresIn != "" {
				duration, err := time.ParseDuration(expiresIn)
				if err != nil || duration <= 0 {
					return cmdutil.FlagErrorf("expires-in must be a positive duration")
				}
				value := now().Add(duration)
				expiresAt = &value
			}
			issued, err := service.Issue(cmd.Context(), broker.IssueRequest{
				CredentialName: credential,
				Repository: broker.RepositoryRequest{
					Owner: owner, Name: name, ExpectedID: optionalPositiveInt64(expectedRepositoryID),
				},
				Policy:    policy,
				ExpiresAt: expiresAt,
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), issued.Token)
			return nil
		},
	}
	issue.Flags().StringVar(&credential, "credential", "", "stored upstream credential name")
	issue.Flags().StringVar(&repo, "repo", "", "target repository as OWNER/NAME")
	issue.Flags().Int64Var(&expectedRepositoryID, "expected-repository-id", 0, "optional immutable GitHub repository ID assertion")
	issue.Flags().StringVar(&profile, "policy", "developer", "policy profile name")
	issue.Flags().IntVar(&policyVersion, "policy-version", 1, "policy profile version")
	issue.Flags().StringSliceVar(&grants, "grant", nil, "additional policy grant")
	issue.Flags().StringVar(&gitPush, "git-push", broker.GitPushNone, "Git branch push tier: none, non-default, or all")
	issue.Flags().BoolVar(&gitTags, "git-tags", false, "allow Git tag creation and updates")
	issue.Flags().StringVar(&expiresIn, "expires-in", "", "optional capability lifetime")
	for _, required := range []string{"credential", "repo"} {
		_ = issue.MarkFlagRequired(required)
	}

	revoke := &cobra.Command{
		Use:   "revoke CAPABILITY_ID",
		Short: "Revoke a capability immediately",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if service == nil {
				return errors.New("admin service is unavailable")
			}
			if !strings.HasPrefix(args[0], "cap_") {
				return cmdutil.FlagErrorf("invalid capability ID %s", strconv.Quote(args[0]))
			}
			return service.Revoke(cmd.Context(), args[0])
		},
	}
	capability.AddCommand(issue, revoke, newCapabilityPolicyCommand(service))
	return capability
}

func newCapabilityPolicyCommand(service Service) *cobra.Command {
	policy := &cobra.Command{Use: "policy", Short: "Inspect and replace capability policies"}
	policy.AddCommand(newPolicyShowCommand(service), newPolicyReplaceCommand(service), newPolicyHistoryCommand(service))
	return policy
}

func newPolicyShowCommand(service Service) *cobra.Command {
	return &cobra.Command{
		Use:   "show CAPABILITY_ID",
		Short: "Print the current capability policy as JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if service == nil {
				return errors.New("admin service is unavailable")
			}
			if err := validateCapabilityID(args[0]); err != nil {
				return err
			}
			view, err := service.ShowPolicy(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(view)
		},
	}
}

type policyReplaceOptions struct {
	service      Service
	context      context.Context
	stdout       io.Writer
	capabilityID string
	grants       []string
	noGrants     bool
	gitPush      string
	gitTags      bool
	gitTagsSet   bool
	reason       string
	actor        string
}

func newPolicyReplaceCommand(service Service) *cobra.Command {
	opts := &policyReplaceOptions{service: service}
	command := &cobra.Command{
		Use:   "replace CAPABILITY_ID",
		Short: "Atomically replace an active capability's customizable policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.context = cmd.Context()
			opts.stdout = cmd.OutOrStdout()
			opts.capabilityID = args[0]
			opts.gitTagsSet = cmd.Flags().Changed("git-tags")
			return policyReplaceRun(opts)
		},
	}
	command.Flags().StringSliceVar(&opts.grants, "grant", nil, "complete additional policy grant set")
	command.Flags().BoolVar(&opts.noGrants, "no-grants", false, "replace with no additional policy grants")
	command.Flags().StringVar(&opts.gitPush, "git-push", "", "Git branch push tier: none, non-default, or all")
	command.Flags().BoolVar(&opts.gitTags, "git-tags", false, "whether Git tag creation and updates are allowed")
	command.Flags().StringVar(&opts.reason, "reason", "", "required reason recorded in permanent policy history")
	command.Flags().StringVar(&opts.actor, "actor", "", "optional unverified operator label")
	return command
}

func policyReplaceRun(opts *policyReplaceOptions) error {
	if opts.service == nil {
		return errors.New("admin service is unavailable")
	}
	if err := validateCapabilityID(opts.capabilityID); err != nil {
		return err
	}
	if opts.gitPush != broker.GitPushNone && opts.gitPush != broker.GitPushNonDefault && opts.gitPush != broker.GitPushAll {
		return cmdutil.FlagErrorf("git-push must be explicitly set to none, non-default, or all")
	}
	if !opts.gitTagsSet {
		return cmdutil.FlagErrorf("git-tags must be explicitly set to true or false")
	}
	if len(opts.grants) == 0 && !opts.noGrants {
		return cmdutil.FlagErrorf("either grant or no-grants must be specified")
	}
	if len(opts.grants) > 0 && opts.noGrants {
		return cmdutil.FlagErrorf("grant and no-grants are mutually exclusive")
	}
	grants := make(map[string]bool, len(opts.grants))
	for _, grant := range opts.grants {
		if !broker.IsKnownGrant(grant) {
			return cmdutil.FlagErrorf("unknown policy grant %q", grant)
		}
		if grants[grant] {
			return cmdutil.FlagErrorf("duplicate policy grant %q", grant)
		}
		grants[grant] = true
	}
	if strings.TrimSpace(opts.reason) == "" {
		return cmdutil.FlagErrorf("reason is required")
	}
	result, err := opts.service.ReplacePolicy(opts.context, ReplacePolicyRequest{
		CapabilityID: opts.capabilityID,
		Policy: broker.Policy{
			Name: "developer", Version: 1, Grants: grants,
			Git: broker.GitPolicy{Push: opts.gitPush, Tags: opts.gitTags},
		},
		Reason: opts.reason, Actor: opts.actor,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(opts.stdout).Encode(result)
}

type policyHistoryOptions struct {
	service      Service
	context      context.Context
	stdout       io.Writer
	capabilityID string
	sinceValue   string
	limit        int
}

func newPolicyHistoryCommand(service Service) *cobra.Command {
	opts := &policyHistoryOptions{service: service, limit: 100}
	command := &cobra.Command{
		Use:   "history CAPABILITY_ID",
		Short: "Print permanent capability policy history as JSON lines",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.context = cmd.Context()
			opts.stdout = cmd.OutOrStdout()
			opts.capabilityID = args[0]
			return policyHistoryRun(opts)
		},
	}
	command.Flags().StringVar(&opts.sinceValue, "since", "", "filter at or after an RFC3339 timestamp")
	command.Flags().IntVar(&opts.limit, "limit", opts.limit, "maximum events to return (1-1000)")
	return command
}

func policyHistoryRun(opts *policyHistoryOptions) error {
	if opts.service == nil {
		return errors.New("admin service is unavailable")
	}
	if err := validateCapabilityID(opts.capabilityID); err != nil {
		return err
	}
	if opts.limit <= 0 || opts.limit > 1000 {
		return cmdutil.FlagErrorf("limit must be between 1 and 1000")
	}
	var since *time.Time
	if opts.sinceValue != "" {
		parsed, err := time.Parse(time.RFC3339, opts.sinceValue)
		if err != nil {
			return cmdutil.FlagErrorf("since must be an RFC3339 timestamp")
		}
		since = &parsed
	}
	events, err := opts.service.ListPolicyHistory(opts.context, broker.CapabilityPolicyHistoryQuery{
		CapabilityID: opts.capabilityID, Since: since, Limit: opts.limit,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(opts.stdout)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("write capability policy event: %w", err)
		}
	}
	return nil
}

func validateCapabilityID(id string) error {
	if !strings.HasPrefix(id, "cap_") || len(id) == len("cap_") {
		return cmdutil.FlagErrorf("invalid capability ID %s", strconv.Quote(id))
	}
	return nil
}

func optionalPositiveInt64(value int64) *int64 {
	if value <= 0 {
		return nil
	}
	return &value
}
