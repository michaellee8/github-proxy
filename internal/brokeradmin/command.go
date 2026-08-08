package brokeradmin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/spf13/cobra"
)

// PutCredentialRequest contains an Upstream Credential read by the offline admin CLI.
type PutCredentialRequest struct {
	Name         string
	UpstreamHost string
	APIBaseURL   string
	APIVersion   string
	Token        []byte
}

// Service is the privileged administrative boundary. It is never exposed over HTTP.
type Service interface {
	PutCredential(context.Context, PutCredentialRequest) error
	Issue(context.Context, broker.IssueRequest) (broker.IssuedCapability, error)
	Revoke(context.Context, string) error
}

// NewCommand constructs the offline pgh-broker administrative command tree.
func NewCommand(service Service, stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "pgh-broker",
		Short:         "Administer repository-scoped GitHub capabilities",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newCredentialCommand(service), newCapabilityCommand(service))
	return root
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
	_ = put.MarkFlagRequired("name")
	_ = put.MarkFlagRequired("host")
	credential.AddCommand(put)
	return credential
}

func newCapabilityCommand(service Service) *cobra.Command {
	capability := &cobra.Command{Use: "capability", Short: "Issue and revoke repository capabilities"}
	var credential, repo, defaultBranch, profile, expiresIn, gitPush string
	var repositoryID int64
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
				return errors.New("repo must be exactly OWNER/NAME")
			}
			policyGrants := make(map[string]bool, len(grants))
			for _, grant := range grants {
				if !broker.IsKnownGrant(grant) {
					return fmt.Errorf("unknown policy grant %q", grant)
				}
				policyGrants[grant] = true
			}
			if gitPush != broker.GitPushNone && gitPush != broker.GitPushNonDefault && gitPush != broker.GitPushAll {
				return errors.New("git-push must be none, non-default, or all")
			}
			var expiresAt *time.Time
			if expiresIn != "" {
				duration, err := time.ParseDuration(expiresIn)
				if err != nil || duration <= 0 {
					return errors.New("expires-in must be a positive duration")
				}
				value := time.Now().Add(duration)
				expiresAt = &value
			}
			issued, err := service.Issue(cmd.Context(), broker.IssueRequest{
				CredentialName: credential,
				Repository:     broker.Repository{ID: repositoryID, Owner: owner, Name: name, DefaultBranch: defaultBranch},
				Policy:         broker.Policy{Name: profile, Version: policyVersion, Grants: policyGrants, Git: broker.GitPolicy{Push: gitPush, Tags: gitTags}},
				ExpiresAt:      expiresAt,
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
	issue.Flags().Int64Var(&repositoryID, "repository-id", 0, "immutable GitHub repository ID")
	issue.Flags().StringVar(&defaultBranch, "default-branch", "", "target repository default branch")
	issue.Flags().StringVar(&profile, "policy", "developer", "policy profile name")
	issue.Flags().IntVar(&policyVersion, "policy-version", 1, "policy profile version")
	issue.Flags().StringSliceVar(&grants, "grant", nil, "additional policy grant")
	issue.Flags().StringVar(&gitPush, "git-push", broker.GitPushNone, "Git branch push tier: none, non-default, or all")
	issue.Flags().BoolVar(&gitTags, "git-tags", false, "allow Git tag creation and updates")
	issue.Flags().StringVar(&expiresIn, "expires-in", "", "optional capability lifetime")
	for _, required := range []string{"credential", "repo", "repository-id", "default-branch"} {
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
				return fmt.Errorf("invalid capability ID %s", strconv.Quote(args[0]))
			}
			return service.Revoke(cmd.Context(), args[0])
		},
	}
	capability.AddCommand(issue, revoke)
	return capability
}
