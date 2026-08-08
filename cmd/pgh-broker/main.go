package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
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
	command := brokeradmin.NewCommand(runtime, os.Stdin, os.Stdout, os.Stderr)
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
}

func (r *brokerRuntime) initialize(ctx context.Context) error {
	r.once.Do(func() {
		databaseURL := os.Getenv("PGH_DATABASE_URL")
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
		r.pool = pool
		r.store = store
		r.cipher = cipher
		r.admin = brokeradmin.NewAdminService(store, cipher, rand.Reader, time.Now)
		r.authority = broker.NewCapabilityAuthority(store, cipher, time.Now)
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

func (r *brokerRuntime) Serve(ctx context.Context, address string) error {
	if err := r.initialize(ctx); err != nil {
		return err
	}
	server := &http.Server{
		Addr:              address,
		Handler:           broker.NewHandler(broker.HandlerOptions{Authority: r.authority}),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.ListenAndServe()
	if r.pool != nil {
		r.pool.Close()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
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

var _ brokeradmin.Service = (*brokerRuntime)(nil)
