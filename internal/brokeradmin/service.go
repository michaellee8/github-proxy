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

	"github.com/cli/cli/v2/internal/broker"
)

// Store is the privileged persistence adapter used by the offline service.
type Store interface {
	broker.CapabilityStore
	PutCredential(context.Context, broker.StoredCredential) error
	RevokeCapability(context.Context, string, time.Time) error
}

// AdminService encrypts credentials and manages Repository Capabilities.
type AdminService struct {
	store  Store
	cipher *broker.CredentialCipher
	random io.Reader
	now    func() time.Time
}

// NewAdminService constructs the offline credential and capability service.
func NewAdminService(store Store, cipher *broker.CredentialCipher, random io.Reader, now func() time.Time) *AdminService {
	return &AdminService{store: store, cipher: cipher, random: random, now: now}
}

// PutCredential encrypts and stores an upstream GitHub credential.
func (s *AdminService) PutCredential(ctx context.Context, request PutCredentialRequest) error {
	if s.store == nil || s.cipher == nil || s.random == nil || request.Name == "" || request.UpstreamHost == "" || len(request.Token) == 0 {
		return errors.New("complete upstream credential settings are required")
	}
	apiBase, err := url.Parse(request.APIBaseURL)
	if err != nil || apiBase.Scheme != "https" || apiBase.Host == "" || apiBase.User != nil || apiBase.RawQuery != "" || apiBase.Fragment != "" {
		return errors.New("API base URL must be an HTTPS URL without credentials, query, or fragment")
	}
	if !strings.EqualFold(apiBase.Hostname(), request.UpstreamHost) && !(strings.EqualFold(request.UpstreamHost, "github.com") && strings.EqualFold(apiBase.Hostname(), "api.github.com")) {
		return errors.New("API base URL must belong to the upstream host")
	}
	sealed, err := s.cipher.Encrypt(request.Token)
	if err != nil {
		return fmt.Errorf("encrypt upstream credential: %w", err)
	}
	idBytes := make([]byte, 12)
	if _, err := io.ReadFull(s.random, idBytes); err != nil {
		return fmt.Errorf("generate credential ID: %w", err)
	}
	credential := broker.StoredCredential{
		ID: "cred_" + base64.RawURLEncoding.EncodeToString(idBytes), Name: request.Name,
		UpstreamHost: request.UpstreamHost, APIBaseURL: request.APIBaseURL, APIVersion: request.APIVersion, Token: sealed,
	}
	return s.store.PutCredential(ctx, credential)
}

// Issue creates a repository-bound capability and returns its token once.
func (s *AdminService) Issue(ctx context.Context, request broker.IssueRequest) (broker.IssuedCapability, error) {
	issuer := broker.NewCapabilityIssuer(s.store, s.random, s.now)
	return issuer.Issue(ctx, request)
}

// Revoke permanently disables a repository capability.
func (s *AdminService) Revoke(ctx context.Context, id string) error {
	if s.store == nil || s.now == nil {
		return errors.New("admin service is unavailable")
	}
	return s.store.RevokeCapability(ctx, id, s.now())
}

var _ Service = (*AdminService)(nil)
