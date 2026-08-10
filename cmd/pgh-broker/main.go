package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/cli/cli/v2/internal/brokeradmin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runtime := &brokerRuntime{}
	command := brokeradmin.NewCommand(brokeradmin.CommandOptions{
		Service: runtime, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Now: time.Now,
	})
	command.SetContext(ctx)
	command.AddCommand(newServeCommand(runtime))
	if err := command.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

type brokerRuntime struct {
	once      sync.Once
	err       error
	pool      *pgxpool.Pool
	store     *broker.PostgresStore
	cipher    *broker.CredentialCipher
	admin     *brokeradmin.AdminService
	authority broker.Authority
	auditor   broker.RequestAuditor
	limiter   broker.RequestLimiter
	retention time.Duration
	logger    *slog.Logger
}

func (r *brokerRuntime) initialize(ctx context.Context) error {
	r.once.Do(func() {
		databaseURL, err := databaseURLWithTLS(os.Getenv("PGH_DATABASE_URL"), os.Getenv("PGH_ALLOW_INSECURE_DATABASE") == "true")
		if err != nil {
			r.err = err
			return
		}
		cacheTTL, err := repositoryCacheTTL(os.Getenv("PGH_REPOSITORY_CACHE_TTL"))
		if err != nil {
			r.err = err
			return
		}
		retention, err := auditRetention(os.Getenv("PGH_AUDIT_RETENTION"))
		if err != nil {
			r.err = err
			return
		}
		if databaseURL == "" {
			r.err = errors.New("PGH_DATABASE_URL is required")
			return
		}
		activeKeyID := os.Getenv("PGH_ACTIVE_KEY_ID")
		keys, err := parseKeyring(os.Getenv("PGH_ENCRYPTION_KEYS"))
		if err != nil {
			r.err = err
			return
		}
		cipher, err := broker.NewCredentialCipher(activeKeyID, keys, rand.Reader)
		if err != nil {
			r.err = fmt.Errorf("configure credential encryption: %w", err)
			return
		}
		pool, err := pgxpool.New(ctx, databaseURL)
		if err != nil {
			r.err = fmt.Errorf("configure PostgreSQL: %w", err)
			return
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			r.err = fmt.Errorf("connect to PostgreSQL: %w", err)
			return
		}
		if err := broker.Migrate(ctx, pool); err != nil {
			pool.Close()
			r.err = err
			return
		}
		store := broker.NewPostgresStore(pool)
		resolver := broker.NewRepositoryResolver(http.DefaultTransport, time.Now, cacheTTL)
		limiter, err := broker.NewLocalRequestLimiter(broker.LocalLimitOptions{
			ReadsPerMinute: 300, MutationsPerMinute: 60, Concurrent: 8,
		})
		if err != nil {
			pool.Close()
			r.err = fmt.Errorf("configure local request limits: %w", err)
			return
		}
		logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		r.pool = pool
		r.store = store
		r.cipher = cipher
		r.admin = brokeradmin.NewAdminService(store, cipher, resolver, rand.Reader, time.Now)
		r.authority = broker.NewCapabilityAuthority(store, cipher, resolver, time.Now)
		r.auditor = broker.NewRequestAuditor(store, broker.NewJSONAuditEmitter(os.Stderr))
		r.limiter = limiter
		r.retention = retention
		r.logger = logger
	})
	return r.err
}

func (r *brokerRuntime) PutCredential(ctx context.Context, request brokeradmin.PutCredentialRequest) error {
	if err := r.initialize(ctx); err != nil {
		return err
	}
	return r.admin.PutCredential(ctx, request)
}

func (r *brokerRuntime) Issue(ctx context.Context, request broker.IssueRequest) (broker.IssuedCapability, error) {
	if err := r.initialize(ctx); err != nil {
		return broker.IssuedCapability{}, err
	}
	return r.admin.Issue(ctx, request)
}

func (r *brokerRuntime) Revoke(ctx context.Context, id string) error {
	if err := r.initialize(ctx); err != nil {
		return err
	}
	return r.admin.Revoke(ctx, id)
}

func (r *brokerRuntime) ListAuditEvents(ctx context.Context, query broker.AuditQuery) ([]broker.AuditEvent, error) {
	if err := r.initialize(ctx); err != nil {
		return nil, err
	}
	return r.admin.ListAuditEvents(ctx, query)
}

func (r *brokerRuntime) Serve(ctx context.Context, address string) error {
	if err := r.initialize(ctx); err != nil {
		return err
	}
	server := &http.Server{
		Addr: address,
		Handler: broker.NewHandler(broker.HandlerOptions{
			Authority: r.authority, Auditor: r.auditor, Limiter: r.limiter,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	retentionCtx, stopRetention := context.WithCancel(ctx)
	go r.runAuditRetention(retentionCtx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.ListenAndServe()
	stopRetention()
	if r.pool != nil {
		r.pool.Close()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (r *brokerRuntime) runAuditRetention(ctx context.Context) {
	prune := func() {
		deleted, err := r.store.DeleteAuditEventsBefore(ctx, time.Now().Add(-r.retention))
		if err != nil {
			r.logger.ErrorContext(ctx, "audit retention failed", "error", err)
			return
		}
		if deleted > 0 {
			r.logger.InfoContext(ctx, "expired audit events deleted", "count", deleted)
		}
	}
	prune()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}

func newServeCommand(runtime *brokerRuntime) *cobra.Command {
	defaultAddress := os.Getenv("PGH_LISTEN_ADDR")
	if defaultAddress == "" {
		defaultAddress = "127.0.0.1:8080"
	}
	var address string
	command := &cobra.Command{
		Use:   "serve",
		Short: "Run the repository access Broker",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runtime.Serve(cmd.Context(), address)
		},
	}
	command.Flags().StringVar(&address, "listen", defaultAddress, "HTTP listen address (terminate TLS in front of this service)")
	return command
}

func parseKeyring(value string) (map[string][]byte, error) {
	if value == "" {
		return nil, errors.New("PGH_ENCRYPTION_KEYS is required")
	}
	keys := make(map[string][]byte)
	for _, entry := range strings.Split(value, ",") {
		id, encoded, ok := strings.Cut(entry, ":")
		if !ok || id == "" || encoded == "" {
			return nil, errors.New("PGH_ENCRYPTION_KEYS must contain key-id:base64 entries")
		}
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("encryption key %s must be 32 bytes encoded as base64", id)
		}
		if _, duplicate := keys[id]; duplicate {
			return nil, fmt.Errorf("duplicate encryption key ID %s", id)
		}
		keys[id] = key
	}
	return keys, nil
}

func databaseURLWithTLS(value string, allowInsecure bool) (string, error) {
	if value == "" {
		return "", errors.New("PGH_DATABASE_URL is required")
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		return "", errors.New("PGH_DATABASE_URL must be a PostgreSQL URL")
	}
	query := parsed.Query()
	mode := query.Get("sslmode")
	if mode == "" {
		mode = "verify-full"
		query.Set("sslmode", mode)
	}
	if mode != "verify-full" && !allowInsecure {
		return "", errors.New("PGH_DATABASE_URL must use sslmode=verify-full; set PGH_ALLOW_INSECURE_DATABASE=true only for development")
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func repositoryCacheTTL(value string) (time.Duration, error) {
	if value == "" {
		return broker.NormalizeRepositoryObservationTTL(0), nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, errors.New("PGH_REPOSITORY_CACHE_TTL must be a positive duration")
	}
	return broker.NormalizeRepositoryObservationTTL(duration), nil
}

func auditRetention(value string) (time.Duration, error) {
	if value == "" {
		return 90 * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, errors.New("PGH_AUDIT_RETENTION must be a positive duration")
	}
	return duration, nil
}

var _ brokeradmin.Service = (*brokerRuntime)(nil)
