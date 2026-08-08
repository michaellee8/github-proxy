package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPGHHelpUsesPGHIdentityAndPreservesUpstreamCommands(t *testing.T) {
	result := runPGH(t, "--help")

	require.Equal(t, 0, result.exitCode, result.stderr)
	require.Contains(t, result.stdout, "pgh <command> <subcommand> [flags]")
	require.NotContains(t, result.stdout, "\n  gh <command> <subcommand> [flags]")
	require.Contains(t, result.stdout, "--version   Show pgh version")
	require.Contains(t, result.stdout, "Use `pgh <command> <subcommand> --help`")
	require.NotContains(t, result.stdout, "Use `gh <command> <subcommand> --help`")
	for _, command := range []string{"issue", "pr", "repo"} {
		require.Contains(t, result.stdout, command)
	}
}

func TestPGHVersionUsesPGHIdentity(t *testing.T) {
	result := runPGH(t, "--version")

	require.Equal(t, 0, result.exitCode, result.stderr)
	require.True(t, strings.HasPrefix(result.stdout, "pgh version "), result.stdout)
}

func TestPGHAuthenticationHelpStaysWithinPGH(t *testing.T) {
	result := runPGH(t, "issue", "list")

	require.NotEqual(t, 0, result.exitCode)
	require.Contains(t, result.stderr, "pgh auth login")
	require.Contains(t, result.stderr, "PGH_TOKEN")
	require.NotContains(t, result.stderr, "please run:  gh auth login")
}

func TestPGHSubcommandHelpUsesPGHIdentity(t *testing.T) {
	result := runPGH(t, "pr", "--help")

	require.Equal(t, 0, result.exitCode, result.stderr)
	require.Contains(t, result.stdout, "$ pgh pr checkout 353")
	require.NotContains(t, result.stdout, "$ gh pr checkout 353")
}

func TestPGHUsesAnIsolatedConfigDirectory(t *testing.T) {
	home := t.TempDir()
	configHome := filepath.Join(home, ".config")
	ghConfigDir := filepath.Join(configHome, "gh")
	result := runPGHWithEnv(t, map[string]string{
		"HOME":            home,
		"XDG_CONFIG_HOME": configHome,
		"GH_CONFIG_DIR":   ghConfigDir,
	}, "config", "set", "editor", "pgh-editor")

	require.Equal(t, 0, result.exitCode, result.stderr)
	_, err := os.Stat(filepath.Join(configHome, "pgh", "config.yml"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(ghConfigDir, "config.yml"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestPGHEnvironmentPolicy(t *testing.T) {
	tests := []struct {
		name               string
		environment        map[string]string
		args               []string
		wantExitCode       int
		wantStdout         string
		wantStderrContains string
	}{
		{
			name: "PGH variables take precedence",
			environment: map[string]string{
				"PGH_HOST":  "broker.example.com",
				"PGH_TOKEN": "pgh-capability",
				"GH_HOST":   "fallback.example.com",
				"GH_TOKEN":  "gh-capability",
			},
			args:         []string{"auth", "token"},
			wantStdout:   "pgh-capability\n",
			wantExitCode: 0,
		},
		{
			name: "GH variables are capability fallbacks",
			environment: map[string]string{
				"GH_HOST":  "broker.example.com",
				"GH_TOKEN": "fallback-capability",
			},
			args:         []string{"auth", "token"},
			wantStdout:   "fallback-capability\n",
			wantExitCode: 0,
		},
		{
			name: "github.com environment host is rejected",
			environment: map[string]string{
				"PGH_HOST":  "github.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"auth", "token"},
			wantExitCode:       1,
			wantStderrContains: "pgh refuses direct GitHub host github.com",
		},
		{
			name: "api.github.com environment host is rejected",
			environment: map[string]string{
				"PGH_HOST":  "api.github.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"auth", "token"},
			wantExitCode:       1,
			wantStderrContains: "pgh refuses direct GitHub host api.github.com",
		},
		{
			name: "command host override cannot bypass broker",
			environment: map[string]string{
				"PGH_HOST":  "broker.example.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"api", "user", "--hostname", "github.com"},
			wantExitCode:       1,
			wantStderrContains: "pgh refuses command host github.com; configured broker host is broker.example.com",
		},
		{
			name: "absolute API URL cannot bypass broker",
			environment: map[string]string{
				"PGH_HOST":  "broker.example.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"api", "https://api.github.com/user"},
			wantExitCode:       1,
			wantStderrContains: "pgh refuses request to api.github.com; configured broker host is broker.example.com",
		},
		{
			name: "broker capability requires HTTPS",
			environment: map[string]string{
				"PGH_HOST":  "broker.example.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"api", "http://broker.example.com/user"},
			wantExitCode:       1,
			wantStderrContains: "pgh refuses insecure request to broker.example.com",
		},
		{
			name: "alternate broker port is rejected",
			environment: map[string]string{
				"PGH_HOST":  "broker.example.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"api", "https://broker.example.com:8443/user"},
			wantExitCode:       1,
			wantStderrContains: "pgh refuses request authority broker.example.com:8443; configured broker host is broker.example.com",
		},
		{
			name: "capability is not resolved for GitHub",
			environment: map[string]string{
				"PGH_HOST":  "broker.example.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"auth", "token", "--hostname", "github.com"},
			wantExitCode:       1,
			wantStderrContains: "pgh refuses command host github.com; configured broker host is broker.example.com",
		},
		{
			name: "secure storage cannot read GitHub credentials",
			environment: map[string]string{
				"PGH_HOST":  "broker.example.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"auth", "token", "--secure-storage", "--hostname", "github.com"},
			wantExitCode:       1,
			wantStderrContains: "pgh refuses command host github.com; configured broker host is broker.example.com",
		},
		{
			name: "broker host must not be a URL",
			environment: map[string]string{
				"PGH_HOST":  "https://broker.example.com",
				"PGH_TOKEN": "pgh-capability",
			},
			args:               []string{"auth", "token"},
			wantExitCode:       1,
			wantStderrContains: "invalid pgh broker host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runPGHWithEnv(t, tt.environment, tt.args...)

			require.Equal(t, tt.wantExitCode, result.exitCode, result.stderr)
			require.Equal(t, tt.wantStdout, result.stdout)
			if tt.wantStderrContains != "" {
				require.Contains(t, result.stderr, tt.wantStderrContains)
			}
		})
	}
}

func TestPGHUsesBrokerHostFromItsIsolatedConfig(t *testing.T) {
	configDir := t.TempDir()
	setup := runPGHWithEnv(t, map[string]string{
		"PGH_CONFIG_DIR": configDir,
		"PGH_HOST":       "broker.example.com",
	}, "config", "set", "git_protocol", "https", "--host", "broker.example.com")
	require.Equal(t, 0, setup.exitCode, setup.stderr)

	result := runPGHWithEnv(t, map[string]string{
		"PGH_CONFIG_DIR": configDir,
		"PGH_TOKEN":      "pgh-capability",
	}, "api", "user", "--hostname", "github.com")

	require.Equal(t, 1, result.exitCode)
	require.Contains(t, result.stderr, "configured broker host is broker.example.com")
}

type commandResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func runPGH(t *testing.T, args ...string) commandResult {
	t.Helper()
	return runPGHWithEnv(t, nil, args...)
}

func runPGHWithEnv(t *testing.T, overrides map[string]string, args ...string) commandResult {
	t.Helper()

	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	cmd.Dir = "."
	cmd.Env = cleanEnvironment(t, overrides)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr)
		exitCode = exitErr.ExitCode()
	}

	return commandResult{
		exitCode: exitCode,
		stdout:   stdout.String(),
		stderr:   stderr.String(),
	}
}

func cleanEnvironment(t *testing.T, overrides map[string]string) []string {
	t.Helper()

	home := t.TempDir()
	envValues := map[string]string{}
	for _, item := range os.Environ() {
		key, value, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "GO") || key == "CC" || key == "CGO_ENABLED" {
			envValues[key] = value
		}
	}
	envValues["HOME"] = home
	envValues["XDG_CONFIG_HOME"] = filepath.Join(home, ".config")
	envValues["PATH"] = os.Getenv("PATH")
	envValues["GOCACHE"] = goEnv(t, "GOCACHE")
	envValues["GOMODCACHE"] = goEnv(t, "GOMODCACHE")
	envValues["GOPATH"] = goEnv(t, "GOPATH")
	for key, value := range overrides {
		envValues[key] = value
	}

	keys := make([]string, 0, len(envValues))
	for key := range envValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+envValues[key])
	}
	return env
}

func goEnv(t *testing.T, key string) string {
	t.Helper()
	output, err := exec.Command("go", "env", key).Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}
