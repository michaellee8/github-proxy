package brokeradmin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/cli/cli/v2/internal/broker"
)

// Store is the privileged persistence adapter used by the offline service.
type Store interface {
	broker.CapabilityStore
	broker.AuditArchive
	PutCredential(context.Context, broker.StoredCredential) error
	RevokeCapability(context.Context, string, time.Time) error
	CapabilityPolicyByID(context.Context, string, time.Time) (broker.CapabilityPolicyView, error)
	ReplaceCapabilityPolicy(context.Context, broker.CapabilityPolicyReplacement) (broker.CapabilityPolicyReplacementResult, error)
	ListCapabilityPolicyEvents(context.Context, broker.CapabilityPolicyHistoryQuery) ([]broker.CapabilityPolicyEvent, error)
}

// ReplacePolicyRequest contains one complete offline Policy Profile replacement.
type ReplacePolicyRequest struct {
	CapabilityID string
	Policy       broker.Policy
	Reason       string
	Actor        string
}

// AdminService encrypts credentials and manages Repository Capabilities.
type AdminService struct {
	store    Store
	cipher   *broker.CredentialCipher
	resolver *broker.RepositoryResolver
	random   io.Reader
	now      func() time.Time
}

// NewAdminService constructs the offline credential and capability service.
func NewAdminService(store Store, cipher *broker.CredentialCipher, resolver *broker.RepositoryResolver, random io.Reader, now func() time.Time) *AdminService {
	return &AdminService{store: store, cipher: cipher, resolver: resolver, random: random, now: now}
}

// PutCredential encrypts and stores an upstream GitHub credential.
func (s *AdminService) PutCredential(ctx context.Context, request PutCredentialRequest) error {
	if s.store == nil || s.cipher == nil || s.random == nil || request.Name == "" || request.UpstreamHost == "" || len(request.Token) == 0 {
		return errors.New("complete upstream credential settings are required")
	}
	if request.RepositoryResolution != broker.RepositoryResolutionNumeric && request.RepositoryResolution != broker.RepositoryResolutionName {
		return errors.New("repository resolution must be numeric-id or owner-name")
	}
	apiBase, err := url.Parse(request.APIBaseURL)
	if err != nil || apiBase.Scheme != "https" || apiBase.Host == "" || apiBase.User != nil || apiBase.RawQuery != "" || apiBase.Fragment != "" {
		return errors.New("API base URL must be an HTTPS URL without credentials, query, or fragment")
	}
	if !strings.EqualFold(apiBase.Hostname(), request.UpstreamHost) && !(strings.EqualFold(request.UpstreamHost, "github.com") && strings.EqualFold(apiBase.Hostname(), "api.github.com")) {
		return errors.New("API base URL must belong to the upstream host")
	}
	credentialID := ""
	existing, err := s.store.CredentialByName(ctx, request.Name)
	if err == nil {
		credentialID = existing.ID
	} else if !errors.Is(err, broker.ErrCredentialNotFound) {
		return fmt.Errorf("load upstream credential: %w", err)
	}
	if credentialID == "" {
		idBytes := make([]byte, 12)
		if _, err := io.ReadFull(s.random, idBytes); err != nil {
			return fmt.Errorf("generate credential ID: %w", err)
		}
		credentialID = "cred_" + base64.RawURLEncoding.EncodeToString(idBytes)
	}
	credential := broker.StoredCredential{
		ID: credentialID, Name: request.Name,
		UpstreamHost: request.UpstreamHost, APIBaseURL: request.APIBaseURL, APIVersion: request.APIVersion,
		RepositoryResolution: request.RepositoryResolution,
	}
	credential.Token, err = s.cipher.EncryptCredential(credential, request.Token)
	if err != nil {
		return fmt.Errorf("encrypt upstream credential: %w", err)
	}
	return s.store.PutCredential(ctx, credential)
}

// Issue creates a repository-bound capability and returns its token once.
func (s *AdminService) Issue(ctx context.Context, request broker.IssueRequest) (broker.IssuedCapability, error) {
	issuer := broker.NewCapabilityIssuer(s.store, s.cipher, s.resolver, s.random, s.now)
	return issuer.Issue(ctx, request)
}

// Revoke permanently disables a repository capability.
func (s *AdminService) Revoke(ctx context.Context, id string) error {
	if s.store == nil || s.now == nil {
		return errors.New("admin service is unavailable")
	}
	return s.store.RevokeCapability(ctx, id, s.now())
}

// ShowPolicy returns current policy and lifecycle state for one capability.
func (s *AdminService) ShowPolicy(ctx context.Context, id string) (broker.CapabilityPolicyView, error) {
	if s.store == nil || s.now == nil {
		return broker.CapabilityPolicyView{}, errors.New("admin service is unavailable")
	}
	return s.store.CapabilityPolicyByID(ctx, id, s.now())
}

// ReplacePolicy atomically replaces the customizable controls of an active capability.
func (s *AdminService) ReplacePolicy(ctx context.Context, request ReplacePolicyRequest) (broker.CapabilityPolicyReplacementResult, error) {
	if s.store == nil || s.now == nil {
		return broker.CapabilityPolicyReplacementResult{}, errors.New("admin service is unavailable")
	}
	request.Reason = strings.TrimSpace(request.Reason)
	request.Actor = strings.TrimSpace(request.Actor)
	if request.CapabilityID == "" || request.Reason == "" {
		return broker.CapabilityPolicyReplacementResult{}, errors.New("capability ID and policy-change reason are required")
	}
	if len(request.Reason) > 512 || containsControl(request.Reason) {
		return broker.CapabilityPolicyReplacementResult{}, errors.New("policy-change reason must be at most 512 bytes without control characters")
	}
	if len(request.Actor) > 128 || containsControl(request.Actor) {
		return broker.CapabilityPolicyReplacementResult{}, errors.New("policy-change actor must be at most 128 bytes without control characters")
	}
	if err := broker.ValidatePolicy(request.Policy); err != nil {
		return broker.CapabilityPolicyReplacementResult{}, err
	}
	return s.store.ReplaceCapabilityPolicy(ctx, broker.CapabilityPolicyReplacement{
		CapabilityID: request.CapabilityID, Policy: request.Policy, Reason: request.Reason,
		Actor: request.Actor,
	})
}

// ListPolicyHistory returns permanent policy-change events for one capability.
func (s *AdminService) ListPolicyHistory(ctx context.Context, query broker.CapabilityPolicyHistoryQuery) ([]broker.CapabilityPolicyEvent, error) {
	if s.store == nil {
		return nil, errors.New("admin service is unavailable")
	}
	return s.store.ListCapabilityPolicyEvents(ctx, query)
}

// ListAuditEvents returns redacted request records for offline inspection.
func (s *AdminService) ListAuditEvents(ctx context.Context, query broker.AuditQuery) ([]broker.AuditEvent, error) {
	if s.store == nil {
		return nil, errors.New("admin service is unavailable")
	}
	return s.store.ListAuditEvents(ctx, query)
}

var _ Service = (*AdminService)(nil)

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
