package broker

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrCapabilityInvalid  = errors.New("capability is invalid")
	ErrCapabilityNotFound = errors.New("capability not found")
	ErrCredentialNotFound = errors.New("upstream credential not found")
)

// SealedCredential is an authenticated encryption envelope for an Upstream Credential.
type SealedCredential struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

// StoredCredential contains the non-secret upstream settings and encrypted PAT.
type StoredCredential struct {
	ID                   string
	Name                 string
	UpstreamHost         string
	APIBaseURL           string
	APIVersion           string
	RepositoryResolution string
	Token                SealedCredential
}

// StoredCapability is the persistence representation resolved by a CapabilityStore.
type StoredCapability struct {
	ID           string
	Selector     string
	SecretHash   []byte
	CredentialID string
	Credential   StoredCredential
	Repository   Repository
	Policy       Policy
	ExpiresAt    *time.Time
	RevokedAt    *time.Time
}

// CapabilityStore is the persistence boundary used by issuing and resolving capabilities.
type CapabilityStore interface {
	CredentialByName(context.Context, string) (StoredCredential, error)
	CreateCapability(context.Context, StoredCapability) error
	CapabilityBySelector(context.Context, string) (StoredCapability, error)
	UpdateRepositoryObservation(context.Context, string, Repository) error
}

// CredentialCipher encrypts Upstream Credentials with a rotatable keyring.
type CredentialCipher struct {
	activeKeyID string
	keys        map[string][]byte
	random      io.Reader
}

// NewCredentialCipher validates and constructs an AES-256-GCM keyring.
func NewCredentialCipher(activeKeyID string, keys map[string][]byte, random io.Reader) (*CredentialCipher, error) {
	if activeKeyID == "" || random == nil {
		return nil, errors.New("active encryption key and randomness are required")
	}
	keyring := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if id == "" || len(key) != 32 {
			return nil, errors.New("credential encryption keys must be named 32-byte values")
		}
		keyring[id] = append([]byte(nil), key...)
	}
	if _, ok := keyring[activeKeyID]; !ok {
		return nil, errors.New("active credential encryption key is missing")
	}
	return &CredentialCipher{activeKeyID: activeKeyID, keys: keyring, random: random}, nil
}

// EncryptCredential seals a PAT and binds it to its non-secret destination metadata.
func (c *CredentialCipher) EncryptCredential(credential StoredCredential, plaintext []byte) (SealedCredential, error) {
	aead, err := c.aead(c.activeKeyID)
	if err != nil {
		return SealedCredential{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return SealedCredential{}, fmt.Errorf("generate credential nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, credentialAssociatedData(credential, c.activeKeyID))
	return SealedCredential{KeyID: c.activeKeyID, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// DecryptCredential opens a PAT only when its destination metadata is unchanged.
func (c *CredentialCipher) DecryptCredential(credential StoredCredential) ([]byte, error) {
	aead, err := c.aead(credential.Token.KeyID)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, credential.Token.Nonce, credential.Token.Ciphertext, credentialAssociatedData(credential, credential.Token.KeyID))
	if err != nil {
		return nil, errors.New("decrypt upstream credential")
	}
	return plaintext, nil
}

func credentialAssociatedData(credential StoredCredential, keyID string) []byte {
	data, _ := json.Marshal([]string{
		"pgh-credential-v1", keyID, credential.ID, credential.Name, credential.UpstreamHost,
		credential.APIBaseURL, credential.APIVersion, credential.RepositoryResolution,
	})
	return data
}

func (c *CredentialCipher) aead(keyID string) (cipher.AEAD, error) {
	key, ok := c.keys[keyID]
	if !ok {
		return nil, errors.New("credential encryption key is unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize credential cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// IssueRequest describes one immutable Repository Capability.
type IssueRequest struct {
	CredentialName string
	Repository     RepositoryRequest
	Policy         Policy
	ExpiresAt      *time.Time
}

// IssuedCapability returns the only copy of a newly issued bearer token.
type IssuedCapability struct {
	ID    string
	Token string
}

// CapabilityIssuer creates opaque capabilities for the offline admin interface.
type CapabilityIssuer struct {
	store    CapabilityStore
	cipher   *CredentialCipher
	resolver *RepositoryResolver
	random   io.Reader
	now      func() time.Time
}

// NewCapabilityIssuer constructs an issuer over the privileged persistence boundary.
func NewCapabilityIssuer(store CapabilityStore, cipher *CredentialCipher, resolver *RepositoryResolver, random io.Reader, now func() time.Time) *CapabilityIssuer {
	return &CapabilityIssuer{store: store, cipher: cipher, resolver: resolver, random: random, now: now}
}

// Issue creates a repository-bound capability and returns its bearer token once.
func (i *CapabilityIssuer) Issue(ctx context.Context, request IssueRequest) (IssuedCapability, error) {
	if i.store == nil || i.random == nil || request.CredentialName == "" || request.Repository.Owner == "" || request.Repository.Name == "" || request.Policy.Name == "" || request.Policy.Version <= 0 {
		return IssuedCapability{}, errors.New("complete credential, repository, and policy settings are required")
	}
	if err := ValidatePolicy(request.Policy); err != nil {
		return IssuedCapability{}, err
	}
	credential, err := i.store.CredentialByName(ctx, request.CredentialName)
	if err != nil {
		return IssuedCapability{}, fmt.Errorf("load upstream credential: %w", err)
	}
	if i.cipher == nil || i.resolver == nil {
		return IssuedCapability{}, errors.New("repository resolver is unavailable")
	}
	plaintext, err := i.cipher.DecryptCredential(credential)
	if err != nil {
		return IssuedCapability{}, errors.New("decrypt upstream credential")
	}
	repository, err := i.resolver.ResolveByName(ctx, upstreamAccess(credential, plaintext), request.Repository)
	if err != nil {
		return IssuedCapability{}, fmt.Errorf("resolve target repository: %w", err)
	}
	selectorBytes := make([]byte, 12)
	secretBytes := make([]byte, 32)
	if _, err := io.ReadFull(i.random, selectorBytes); err != nil {
		return IssuedCapability{}, fmt.Errorf("generate capability selector: %w", err)
	}
	if _, err := io.ReadFull(i.random, secretBytes); err != nil {
		return IssuedCapability{}, fmt.Errorf("generate capability secret: %w", err)
	}
	selector := base64.RawURLEncoding.EncodeToString(selectorBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	id := "cap_" + selector
	stored := StoredCapability{
		ID: id, Selector: selector, SecretHash: hashCapabilitySecret(secret), CredentialID: credential.ID, Credential: credential,
		Repository: repository, Policy: request.Policy, ExpiresAt: request.ExpiresAt,
	}
	if err := i.store.CreateCapability(ctx, stored); err != nil {
		return IssuedCapability{}, fmt.Errorf("store capability: %w", err)
	}
	return IssuedCapability{ID: id, Token: "pgh_pat_" + selector + "." + secret}, nil
}

func upstreamAccess(credential StoredCredential, plaintext []byte) UpstreamAccess {
	return UpstreamAccess{
		CredentialID: credential.ID, Host: credential.UpstreamHost, APIBaseURL: credential.APIBaseURL,
		APIVersion: credential.APIVersion, RepositoryResolution: credential.RepositoryResolution, Token: string(plaintext),
	}
}

type capabilityAuthority struct {
	store    CapabilityStore
	cipher   *CredentialCipher
	resolver *RepositoryResolver
	now      func() time.Time
}

// NewCapabilityAuthority constructs the request-time capability resolver.
func NewCapabilityAuthority(store CapabilityStore, cipher *CredentialCipher, resolver *RepositoryResolver, now func() time.Time) Authority {
	return &capabilityAuthority{store: store, cipher: cipher, resolver: resolver, now: now}
}

func (a *capabilityAuthority) Resolve(ctx context.Context, token string, freshness RepositoryFreshness) (Session, error) {
	selector, secret, ok := parseCapabilityToken(token)
	if !ok || a.store == nil || a.cipher == nil || a.now == nil {
		return Session{}, ErrCapabilityInvalid
	}
	stored, err := a.store.CapabilityBySelector(ctx, selector)
	if err != nil || subtle.ConstantTimeCompare(stored.SecretHash, hashCapabilitySecret(secret)) != 1 {
		return Session{}, ErrCapabilityInvalid
	}
	now := a.now()
	if stored.RevokedAt != nil || (stored.ExpiresAt != nil && !stored.ExpiresAt.After(now)) {
		return Session{}, ErrCapabilityInvalid
	}
	if err := ValidatePolicy(stored.Policy); err != nil {
		return Session{}, ErrCapabilityInvalid
	}
	plaintext, err := a.cipher.DecryptCredential(stored.Credential)
	if err != nil {
		return Session{}, ErrCapabilityInvalid
	}
	if a.resolver == nil {
		return Session{}, ErrRepositoryIdentity
	}
	access := upstreamAccess(stored.Credential, plaintext)
	repository, err := a.resolver.Resolve(ctx, access, stored.Repository, freshness)
	if err != nil {
		return Session{}, err
	}
	if repository != stored.Repository {
		if err := a.store.UpdateRepositoryObservation(ctx, stored.CredentialID, repository); err != nil {
			return Session{}, ErrRepositoryIdentity
		}
	}
	return Session{
		CapabilityID: stored.ID,
		Repository:   repository,
		Upstream:     access,
		Policy:       stored.Policy,
		ExpiresAt:    stored.ExpiresAt,
	}, nil
}

func parseCapabilityToken(token string) (string, string, bool) {
	remainder, ok := strings.CutPrefix(token, "pgh_pat_")
	if !ok {
		return "", "", false
	}
	selector, secret, ok := strings.Cut(remainder, ".")
	if !ok || selector == "" || secret == "" || len(selector) > 64 || len(secret) > 128 || strings.Contains(secret, ".") {
		return "", "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(selector); err != nil {
		return "", "", false
	}
	if _, err := base64.RawURLEncoding.DecodeString(secret); err != nil {
		return "", "", false
	}
	return selector, secret, true
}

func hashCapabilitySecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
