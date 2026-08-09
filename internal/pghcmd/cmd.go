// Package pghcmd adapts the upstream GitHub CLI process for a pgh broker client.
package pghcmd

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/ghcmd"
	"github.com/cli/cli/v2/internal/ghinstance"
	"github.com/cli/cli/v2/internal/keyring"
	"github.com/spf13/cobra"
)

// Main configures the isolated pgh runtime and runs the upstream command tree.
func Main() int {
	return mainWithOptions(mainOptions{})
}

type mainOptions struct {
	HTTPClientWrapper func(*http.Client) *http.Client
}

func mainWithOptions(opts mainOptions) int {
	host, err := prepareEnvironment()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	clientWrapper := brokerOnlyClientWrapper(host)
	if opts.HTTPClientWrapper != nil {
		clientWrapper = func(client *http.Client) *http.Client {
			return brokerOnlyClientWrapper(host)(opts.HTTPClientWrapper(client))
		}
	}
	return int(ghcmd.MainWithOptions(ghcmd.MainOptions{
		CommandName:       "pgh",
		HTTPClientWrapper: clientWrapper,
		CommandValidator:  brokerOnlyCommandValidator(host),
	}))
}

func prepareEnvironment() (string, error) {
	host := firstNonEmpty(os.Getenv("PGH_HOST"), os.Getenv("GH_HOST"))
	token := firstNonEmpty(os.Getenv("PGH_TOKEN"), os.Getenv("GH_TOKEN"))
	if err := validateBrokerHost(host); err != nil {
		return "", err
	}

	configDir := os.Getenv("PGH_CONFIG_DIR")
	if configDir == "" {
		userConfigDir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve pgh config directory: %w", err)
		}
		configDir = filepath.Join(userConfigDir, "pgh")
	}
	dataDir := filepath.Join(configDir, "data")
	stateDir := filepath.Join(configDir, "state")

	if err := os.Setenv("GH_CONFIG_DIR", configDir); err != nil {
		return "", fmt.Errorf("configure pgh environment variable GH_CONFIG_DIR: %w", err)
	}
	for name, value := range map[string]string{
		"GH_HOST":                 host,
		"GH_TELEMETRY":            "disabled",
		keyring.NamespaceEnv:      "pgh",
		"GH_TOKEN":                "",
		"GH_ENTERPRISE_TOKEN":     token,
		"GITHUB_TOKEN":            "",
		"GITHUB_ENTERPRISE_TOKEN": "",
		"XDG_DATA_HOME":           dataDir,
		"XDG_STATE_HOME":          stateDir,
	} {
		if err := setOrUnsetenv(name, value); err != nil {
			return "", fmt.Errorf("configure pgh environment variable %s: %w", name, err)
		}
	}

	if host == "" {
		cfg, err := config.NewConfig()
		if err != nil {
			return "", fmt.Errorf("read pgh config: %w", err)
		}
		configuredHost, source := cfg.Authentication().DefaultHost()
		if source != "default" {
			if err := validateBrokerHost(configuredHost); err != nil {
				return "", err
			}
			host = configuredHost
			if err := os.Setenv("GH_HOST", host); err != nil {
				return "", fmt.Errorf("configure pgh environment variable GH_HOST: %w", err)
			}
		}
	}
	return host, nil
}

func brokerOnlyClientWrapper(brokerHost string) func(*http.Client) *http.Client {
	return func(client *http.Client) *http.Client {
		transport := client.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		client.Transport = &brokerOnlyTransport{
			brokerHost: strings.ToLower(strings.TrimSuffix(brokerHost, ".")),
			base:       transport,
		}
		return client
	}
}

type brokerOnlyTransport struct {
	brokerHost string
	base       http.RoundTripper
}

func (t *brokerOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	requestHost := strings.ToLower(strings.TrimSuffix(request.URL.Hostname(), "."))
	if t.brokerHost == "" {
		return nil, fmt.Errorf("pgh refuses request to %s; configure a broker host with PGH_HOST", requestHost)
	}
	if request.URL.Scheme != "https" {
		return nil, fmt.Errorf("pgh refuses insecure request to %s; broker requests require HTTPS", requestHost)
	}
	if requestHost != t.brokerHost {
		return nil, fmt.Errorf("pgh refuses request to %s; configured broker host is %s", requestHost, t.brokerHost)
	}
	requestAuthority := strings.ToLower(strings.TrimSuffix(request.URL.Host, "."))
	if request.URL.User != nil || requestAuthority != t.brokerHost {
		return nil, fmt.Errorf("pgh refuses request authority %s; configured broker host is %s", requestAuthority, t.brokerHost)
	}
	return t.base.RoundTrip(request)
}

func brokerOnlyCommandValidator(brokerHost string) func(*cobra.Command) error {
	return func(command *cobra.Command) error {
		if command.Name() == "send-telemetry" {
			return fmt.Errorf("pgh refuses send-telemetry because it does not use the Broker transport")
		}
		for _, flagName := range []string{"hostname", "host"} {
			flag := command.Flags().Lookup(flagName)
			if flag == nil || !flag.Changed {
				continue
			}
			commandHost, err := command.Flags().GetString(flagName)
			if err != nil {
				return err
			}
			if normalizeHost(commandHost) != normalizeHost(brokerHost) {
				if brokerHost == "" {
					return fmt.Errorf("pgh refuses command host %s; configure a broker host with PGH_HOST", commandHost)
				}
				return fmt.Errorf("pgh refuses command host %s; configured broker host is %s", commandHost, brokerHost)
			}
		}
		return nil
	}
}

func validateBrokerHost(host string) error {
	if host == "" {
		return nil
	}
	if host != strings.TrimSpace(host) {
		return fmt.Errorf("invalid pgh broker host %q: surrounding whitespace is not allowed", host)
	}
	if err := ghinstance.HostnameValidator(host); err != nil {
		return fmt.Errorf("invalid pgh broker host %q: %w", host, err)
	}
	normalized := normalizeHost(host)
	if normalized == "github.com" || strings.HasSuffix(normalized, ".github.com") {
		return fmt.Errorf("pgh refuses direct GitHub host %s; configure a broker host with PGH_HOST", host)
	}
	return nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func setOrUnsetenv(name, value string) error {
	if value == "" {
		return os.Unsetenv(name)
	}
	return os.Setenv(name, value)
}
