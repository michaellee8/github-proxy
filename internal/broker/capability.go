package broker

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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
	ID           string
	Name         string
	UpstreamHost string
	APIBaseURL   string
	APIVersion   string
	Token        SealedCredential
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

// Encrypt seals a PAT without retaining the plaintext input.
func (c *CredentialCipher) Encrypt(plaintext []byte) (SealedCredential, error) {
	aead, err := c.aead(c.activeKeyID)
	if err != nil {
		return SealedCredential{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return SealedCredential{}, fmt.Errorf("generate credential nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(c.activeKeyID))
	return SealedCredential{KeyID: c.activeKeyID, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// Decrypt opens an Upstream Credential just before an authorized request.
func (c *CredentialCipher) Decrypt(sealed SealedCredential) ([]byte, error) {
	aead, err := c.aead(sealed.KeyID)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, []byte(sealed.KeyID))
	if err != nil {
		return nil, errors.New("decrypt upstream credential")
	}
	return plaintext, nil
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
	Repository     Repository
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
	store  CapabilityStore
	random io.Reader
	now    func() time.Time
}

func NewCapabilityIssuer(store CapabilityStore, random io.Reader, now func() time.Time) *CapabilityIssuer {
	return &CapabilityIssuer{store: store, random: random, now: now}
}

func (i *CapabilityIssuer) Issue(ctx context.Context, request IssueRequest) (IssuedCapability, error) {
	if i.store == nil || i.random == nil || request.CredentialName == "" || request.Repository.ID <= 0 || request.Repository.Owner == "" || request.Repository.Name == "" || request.Policy.Name == "" || request.Policy.Version <= 0 {
		return IssuedCapability{}, errors.New("complete credential, repository, and policy settings are required")
	}
	credential, err := i.store.CredentialByName(ctx, request.CredentialName)
	if err != nil {
		return IssuedCapability{}, fmt.Errorf("load upstream credential: %w", err)
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
		Repository: request.Repository, Policy: request.Policy, ExpiresAt: request.ExpiresAt,
	}
	if err := i.store.CreateCapability(ctx, stored); err != nil {
		return IssuedCapability{}, fmt.Errorf("store capability: %w", err)
	}
	return IssuedCapability{ID: id, Token: "pgh_pat_" + selector + "." + secret}, nil
}

type capabilityAuthority struct {
	store  CapabilityStore
	cipher *CredentialCipher
	now    func() time.Time
}

func NewCapabilityAuthority(store CapabilityStore, cipher *CredentialCipher, now func() time.Time) Authority {
	return &capabilityAuthority{store: store, cipher: cipher, now: now}
}

func (a *capabilityAuthority) Resolve(ctx context.Context, token string) (Session, error) {
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
	plaintext, err := a.cipher.Decrypt(stored.Credential.Token)
	if err != nil {
		return Session{}, ErrCapabilityInvalid
	}
	repository := stored.Repository
	repository.UpstreamHost = stored.Credential.UpstreamHost
	repository.APIBaseURL = stored.Credential.APIBaseURL
	repository.APIVersion = stored.Credential.APIVersion
	repository.UpstreamToken = string(plaintext)
	return Session{CapabilityID: stored.ID, Repository: repository, Policy: stored.Policy, ExpiresAt: stored.ExpiresAt}, nil
}

func parseCapabilityToken(token string) (string, string, bool) {
	remainder, ok := strings.CutPrefix(token, "pgh_pat_")
	if !ok {
		return "", "", false
	}
	selector, secret, ok := strings.Cut(remainder, ".")
	if !ok || selector == "" || secret == "" || strings.Contains(secret, ".") {
		return "", "", false
	}
	return selector, secret, true
}

func hashCapabilitySecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
