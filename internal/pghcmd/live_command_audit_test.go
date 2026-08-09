package pghcmd

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLivePGHRepositoryCommandAudit(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, _, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")

	const missingID = "999999999"
	const missingName = "pgh-command-audit-missing"
	tests := []struct {
		name           string
		args           []string
		wantNoRequests bool
		wantSuccess    bool
	}{
		{name: "agent-task", args: []string{"agent-task", missingID}, wantNoRequests: true},
		{name: "agent-task create", args: []string{"agent-task", "create", "audit"}, wantNoRequests: true},
		{name: "agent-task view", args: []string{"agent-task", "view", missingID}, wantNoRequests: true},
		{name: "cache delete", args: []string{"cache", "delete", missingID, "--repo", repositoryName}},
		{name: "co", args: []string{"co", missingName, "--repo", repositoryName}},
		{name: "codespace code", args: []string{"codespace", "code", "--codespace", missingName}},
		{name: "codespace cp", args: []string{"codespace", "cp", "--codespace", missingName, "remote:/tmp/a", t.TempDir()}},
		{name: "codespace create", args: []string{"codespace", "create", "--repo", repositoryName, "--machine", "basicLinux32gb"}},
		{name: "codespace delete", args: []string{"codespace", "delete", "--codespace", missingName, "--force"}},
		{name: "codespace edit", args: []string{"codespace", "edit", "--codespace", missingName, "--display-name", "audit"}},
		{name: "codespace jupyter", args: []string{"codespace", "jupyter", "--codespace", missingName}},
		{name: "codespace logs", args: []string{"codespace", "logs", "--codespace", missingName}},
		{name: "codespace ports", args: []string{"codespace", "ports", "--codespace", missingName}},
		{name: "codespace ports forward", args: []string{"codespace", "ports", "forward", "8080:18080", "--codespace", missingName}},
		{name: "codespace ports visibility", args: []string{"codespace", "ports", "visibility", "8080:private", "--codespace", missingName}},
		{name: "codespace rebuild", args: []string{"codespace", "rebuild", "--codespace", missingName}},
		{name: "codespace select", args: []string{"codespace", "select", "--codespace", missingName}},
		{name: "codespace ssh", args: []string{"codespace", "ssh", "--codespace", missingName, "--", "true"}},
		{name: "codespace stop", args: []string{"codespace", "stop", "--codespace", missingName}},
		{name: "codespace view", args: []string{"codespace", "view", "--codespace", missingName}},
		{name: "discussion comment", args: []string{"discussion", "comment", missingID, "--repo", repositoryName, "--body", "audit"}},
		{name: "discussion create", args: []string{"discussion", "create", "--repo", repositoryName, "--title", "audit", "--body", "audit", "--category", "General"}},
		{name: "discussion edit", args: []string{"discussion", "edit", missingID, "--repo", repositoryName, "--title", "audit"}},
		{name: "discussion view", args: []string{"discussion", "view", missingID, "--repo", repositoryName}},
		{name: "issue close", args: []string{"issue", "close", missingID, "--repo", repositoryName}},
		{name: "issue comment", args: []string{"issue", "comment", missingID, "--repo", repositoryName, "--body", "audit"}},
		{name: "issue create", args: []string{"issue", "create", "--repo", repositoryName, "--title", "audit", "--body", "audit", "--label", missingName}},
		{name: "issue delete", args: []string{"issue", "delete", missingID, "--repo", repositoryName, "--yes"}},
		{name: "issue develop", args: []string{"issue", "develop", missingID, "--repo", repositoryName, "--name", missingName}},
		{name: "issue edit", args: []string{"issue", "edit", missingID, "--repo", repositoryName, "--title", "audit"}},
		{name: "issue lock", args: []string{"issue", "lock", missingID, "--repo", repositoryName}},
		{name: "issue pin", args: []string{"issue", "pin", missingID, "--repo", repositoryName}},
		{name: "issue reopen", args: []string{"issue", "reopen", missingID, "--repo", repositoryName}},
		{name: "issue transfer", args: []string{"issue", "transfer", missingID, repositoryName, "--repo", repositoryName}},
		{name: "issue unlock", args: []string{"issue", "unlock", missingID, "--repo", repositoryName}},
		{name: "issue unpin", args: []string{"issue", "unpin", missingID, "--repo", repositoryName}},
		{name: "issue view", args: []string{"issue", "view", missingID, "--repo", repositoryName, "--json", "number"}},
		{name: "label create", args: []string{"label", "create", missingName, "--repo", repositoryName, "--description", strings.Repeat("x", 101)}},
		{name: "label clone", args: []string{"label", "clone", owner + "/" + missingName, "--repo", repositoryName, "--force"}},
		{name: "label delete", args: []string{"label", "delete", missingName, "--repo", repositoryName, "--yes"}},
		{name: "label edit", args: []string{"label", "edit", missingName, "--repo", repositoryName, "--description", "audit"}},
		{name: "pr checkout", args: []string{"pr", "checkout", missingID, "--repo", repositoryName}},
		{name: "pr checks", args: []string{"pr", "checks", missingID, "--repo", repositoryName}},
		{name: "pr close", args: []string{"pr", "close", missingID, "--repo", repositoryName}},
		{name: "pr comment", args: []string{"pr", "comment", missingID, "--repo", repositoryName, "--body", "audit"}},
		{name: "pr create", args: []string{"pr", "create", "--repo", repositoryName, "--head", missingName, "--base", "main", "--title", "audit", "--body", "audit"}},
		{name: "pr diff", args: []string{"pr", "diff", missingID, "--repo", repositoryName}},
		{name: "pr edit", args: []string{"pr", "edit", missingID, "--repo", repositoryName, "--title", "audit"}},
		{name: "pr lock", args: []string{"pr", "lock", missingID, "--repo", repositoryName}},
		{name: "pr merge", args: []string{"pr", "merge", missingID, "--repo", repositoryName, "--merge"}},
		{name: "pr ready", args: []string{"pr", "ready", missingID, "--repo", repositoryName}},
		{name: "pr reopen", args: []string{"pr", "reopen", missingID, "--repo", repositoryName}},
		{name: "pr revert", args: []string{"pr", "revert", missingID, "--repo", repositoryName}},
		{name: "pr review", args: []string{"pr", "review", missingID, "--repo", repositoryName, "--comment", "--body", "audit"}},
		{name: "pr unlock", args: []string{"pr", "unlock", missingID, "--repo", repositoryName}},
		{name: "pr update-branch", args: []string{"pr", "update-branch", missingID, "--repo", repositoryName}},
		{name: "pr view", args: []string{"pr", "view", missingID, "--repo", repositoryName, "--json", "number"}},
		{name: "release create", args: []string{"release", "create", missingName, "--repo", repositoryName, "--target", missingName, "--title", "audit", "--notes", "audit"}},
		{name: "release delete", args: []string{"release", "delete", missingName, "--repo", repositoryName, "--yes"}},
		{name: "release delete-asset", args: []string{"release", "delete-asset", missingName, "asset.txt", "--repo", repositoryName, "--yes"}},
		{name: "release download", args: []string{"release", "download", missingName, "--repo", repositoryName, "--dir", t.TempDir()}},
		{name: "release edit", args: []string{"release", "edit", missingName, "--repo", repositoryName, "--notes", "audit"}},
		{name: "release upload", args: []string{"release", "upload", missingName, os.Args[0], "--repo", repositoryName}},
		{name: "release verify", args: []string{"release", "verify", missingName, "--repo", repositoryName}},
		{name: "release verify-asset", args: []string{"release", "verify-asset", missingName, os.Args[0], "--repo", repositoryName}},
		{name: "repo archive", args: []string{"repo", "archive", repositoryName, "--yes"}},
		{name: "repo autolink create", args: []string{"repo", "autolink", "create", "AUDIT-", "https://example.invalid/<num>", "--repo", repositoryName}},
		{name: "repo autolink delete", args: []string{"repo", "autolink", "delete", missingID, "--repo", repositoryName, "--yes"}},
		{name: "repo autolink view", args: []string{"repo", "autolink", "view", missingID, "--repo", repositoryName}},
		{name: "repo clone", args: []string{"repo", "clone", owner + "/" + missingName, t.TempDir() + "/clone", "--", "--depth=1"}},
		{name: "repo create", args: []string{"repo", "create", missingName, "--private"}},
		{name: "repo credits", args: []string{"repo", "credits", repositoryName}},
		{name: "repo delete", args: []string{"repo", "delete", repositoryName, "--yes"}},
		{name: "repo deploy-key add", args: []string{"repo", "deploy-key", "add", os.Args[0], "--repo", owner + "/" + missingName, "--title", missingName}},
		{name: "repo deploy-key delete", args: []string{"repo", "deploy-key", "delete", missingID, "--repo", repositoryName}},
		{name: "repo edit", args: []string{"repo", "edit", repositoryName, "--description", "audit"}},
		{name: "repo fork", args: []string{"repo", "fork", repositoryName, "--clone=false"}},
		{name: "repo garden", args: []string{"repo", "garden", repositoryName}, wantNoRequests: true},
		{name: "repo rename", args: []string{"repo", "rename", missingName, "--repo", repositoryName, "--yes"}},
		{name: "repo set-default", args: []string{"repo", "set-default", repositoryName}, wantNoRequests: true},
		{name: "repo sync", args: []string{"repo", "sync", repositoryName, "--branch", missingName}},
		{name: "repo unarchive", args: []string{"repo", "unarchive", repositoryName, "--yes"}, wantSuccess: true},
		{name: "ruleset check", args: []string{"ruleset", "check", "main", "--repo", repositoryName}},
		{name: "ruleset view", args: []string{"ruleset", "view", missingID, "--repo", repositoryName}},
		{name: "run cancel", args: []string{"run", "cancel", missingID, "--repo", repositoryName}},
		{name: "run delete", args: []string{"run", "delete", missingID, "--repo", repositoryName}},
		{name: "run download", args: []string{"run", "download", missingID, "--repo", repositoryName, "--dir", t.TempDir()}},
		{name: "run rerun", args: []string{"run", "rerun", missingID, "--repo", repositoryName}},
		{name: "run view", args: []string{"run", "view", missingID, "--repo", repositoryName}},
		{name: "run watch", args: []string{"run", "watch", missingID, "--repo", repositoryName, "--exit-status"}},
		{name: "secret delete", args: []string{"secret", "delete", missingName, "--repo", repositoryName}},
		{name: "secret set", args: []string{"secret", "set", missingName, "--repo", repositoryName, "--body", "audit"}},
		{name: "variable delete", args: []string{"variable", "delete", missingName, "--repo", repositoryName}},
		{name: "variable get", args: []string{"variable", "get", missingName, "--repo", repositoryName}},
		{name: "variable set", args: []string{"variable", "set", missingName, "--repo", repositoryName, "--body", "audit"}},
		{name: "workflow disable", args: []string{"workflow", "disable", missingName, "--repo", repositoryName}},
		{name: "workflow enable", args: []string{"workflow", "enable", missingName, "--repo", repositoryName}},
		{name: "workflow run", args: []string{"workflow", "run", missingName, "--repo", repositoryName, "--ref", "main"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runLivePGH(t, tt.args...)
			wantExitCode := 1
			if tt.wantSuccess {
				wantExitCode = 0
			}
			require.Equal(t, wantExitCode, result.exitCode, result.stderr)
			require.NotEmpty(t, result.stderr)
			require.NotContains(t, result.stderr, token)
			if tt.wantNoRequests {
				require.Empty(t, result.requests)
			} else {
				require.NotEmpty(t, result.requests, "command did not exercise the Broker or GitHub")
			}
		})
	}
}

func TestLivePGHGlobalAndLocalCommandAudit(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, _, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")

	const missingID = "999999999"
	const missingName = "pgh-command-audit-missing"
	isolatedDir := t.TempDir()
	tests := []struct {
		name  string
		args  []string
		stdin string
	}{
		{name: "accessibility", args: []string{"accessibility"}},
		{name: "alias delete", args: []string{"alias", "delete", missingName}},
		{name: "alias import", args: []string{"alias", "import", "-"}, stdin: "audit: version\n"},
		{name: "alias list", args: []string{"alias", "list"}},
		{name: "alias set", args: []string{"alias", "set", "audit", "version"}},
		{name: "attestation download", args: []string{"attestation", "download", os.Args[0], "--repo", repositoryName}},
		{name: "attestation inspect", args: []string{"attestation", "inspect", os.Args[0]}},
		{name: "attestation trusted-root", args: []string{"attestation", "trusted-root", "--verify-only"}},
		{name: "attestation verify", args: []string{"attestation", "verify", os.Args[0], "--repo", repositoryName}},
		{name: "auth git-credential", args: []string{"auth", "git-credential", "get"}, stdin: "protocol=https\nhost=broker.test\n\n"},
		{name: "auth login", args: []string{"auth", "login", "--hostname", "broker.test", "--with-token"}, stdin: "audit-token\n"},
		{name: "auth logout", args: []string{"auth", "logout", "--hostname", "broker.test"}},
		{name: "auth refresh", args: []string{"auth", "refresh", "--hostname", "broker.test", "--scopes", "repo"}},
		{name: "auth setup-git", args: []string{"auth", "setup-git", "--hostname", "github.com"}},
		{name: "auth status", args: []string{"auth", "status", "--hostname", "broker.test"}},
		{name: "auth switch", args: []string{"auth", "switch", "--hostname", "broker.test"}},
		{name: "auth token", args: []string{"auth", "token", "--hostname", "broker.test"}},
		{name: "aw", args: []string{"aw"}},
		{name: "completion", args: []string{"completion", "-s", "bash"}},
		{name: "config clear-cache", args: []string{"config", "clear-cache"}},
		{name: "config get", args: []string{"config", "get", "git_protocol"}},
		{name: "config list", args: []string{"config", "list"}},
		{name: "config set", args: []string{"config", "set", "git_protocol", "https"}},
		{name: "copilot", args: []string{"copilot"}},
		{name: "credits", args: []string{"credits"}},
		{name: "extension browse", args: []string{"extension", "browse"}},
		{name: "extension create", args: []string{"extension", "create"}},
		{name: "extension exec", args: []string{"extension", "exec", missingName}},
		{name: "extension install", args: []string{"extension", "install", owner + "/gh-" + missingName}},
		{name: "extension list", args: []string{"extension", "list"}},
		{name: "extension remove", args: []string{"extension", "remove", missingName}},
		{name: "extension upgrade", args: []string{"extension", "upgrade", missingName}},
		{name: "gist clone", args: []string{"gist", "clone", missingID, isolatedDir + "/gist"}},
		{name: "gist create", args: []string{"gist", "create", "-", "--desc", "audit"}, stdin: "audit\n"},
		{name: "gist delete", args: []string{"gist", "delete", missingID, "--yes"}},
		{name: "gist edit", args: []string{"gist", "edit", missingID, "--add", os.Args[0]}},
		{name: "gist rename", args: []string{"gist", "rename", missingID, "old", "new"}},
		{name: "gist view", args: []string{"gist", "view", missingID}},
		{name: "gpg-key add", args: []string{"gpg-key", "add", os.Args[0]}},
		{name: "gpg-key delete", args: []string{"gpg-key", "delete", missingID, "--yes"}},
		{name: "licenses", args: []string{"licenses"}},
		{name: "preview prompter", args: []string{"preview", "prompter", "input"}},
		{name: "project close", args: []string{"project", "close", missingID, "--owner", owner}},
		{name: "project copy", args: []string{"project", "copy", missingID, "--source-owner", owner, "--target-owner", owner, "--title", "audit"}},
		{name: "project create", args: []string{"project", "create", "--owner", owner, "--title", "audit"}},
		{name: "project delete", args: []string{"project", "delete", missingID, "--owner", owner}},
		{name: "project edit", args: []string{"project", "edit", missingID, "--owner", owner, "--title", "audit"}},
		{name: "project field-create", args: []string{"project", "field-create", missingID, "--owner", owner, "--name", "audit", "--data-type", "TEXT"}},
		{name: "project field-delete", args: []string{"project", "field-delete", "--id", missingID}},
		{name: "project field-list", args: []string{"project", "field-list", missingID, "--owner", owner}},
		{name: "project item-add", args: []string{"project", "item-add", missingID, "--owner", owner, "--url", "https://github.com/" + repositoryName + "/issues/" + missingID}},
		{name: "project item-archive", args: []string{"project", "item-archive", missingID, "--owner", owner, "--id", missingID}},
		{name: "project item-create", args: []string{"project", "item-create", missingID, "--owner", owner, "--title", "audit"}},
		{name: "project item-delete", args: []string{"project", "item-delete", missingID, "--owner", owner, "--id", missingID}},
		{name: "project item-edit", args: []string{"project", "item-edit", "--id", missingID, "--project-id", missingID, "--field-id", missingID, "--text", "audit"}},
		{name: "project item-list", args: []string{"project", "item-list", missingID, "--owner", owner}},
		{name: "project link", args: []string{"project", "link", missingID, "--owner", owner, "--repo", repositoryName}},
		{name: "project mark-template", args: []string{"project", "mark-template", missingID, "--owner", owner}},
		{name: "project unlink", args: []string{"project", "unlink", missingID, "--owner", owner, "--repo", repositoryName}},
		{name: "project view", args: []string{"project", "view", missingID, "--owner", owner}},
		{name: "repo gitignore view", args: []string{"repo", "gitignore", "view", "Go"}},
		{name: "repo license view", args: []string{"repo", "license", "view", "mit"}},
		{name: "search commits", args: []string{"search", "commits", "audit", "--limit", "1"}},
		{name: "search issues", args: []string{"search", "issues", "audit", "--limit", "1"}},
		{name: "search prs", args: []string{"search", "prs", "audit", "--limit", "1"}},
		{name: "search repos", args: []string{"search", "repos", "audit", "--limit", "1"}},
		{name: "send-telemetry", args: []string{"send-telemetry"}, stdin: `{"events":[{"type":"command-audit"}]}`},
		{name: "skill install", args: []string{"skill", "install", owner + "/" + missingName}},
		{name: "skill list", args: []string{"skill", "list"}},
		{name: "skill preview", args: []string{"skill", "preview", owner + "/" + missingName}},
		{name: "skill publish", args: []string{"skill", "publish", isolatedDir}},
		{name: "skill update", args: []string{"skill", "update", missingName}},
		{name: "ssh-key add", args: []string{"ssh-key", "add", os.Args[0], "--title", "audit"}},
		{name: "ssh-key delete", args: []string{"ssh-key", "delete", missingID, "--yes"}},
		{name: "stack", args: []string{"stack"}},
		{name: "version", args: []string{"version"}},
	}
	successfulCommands := map[string]bool{
		"accessibility": true, "alias import": true, "alias list": true, "alias set": true,
		"auth git-credential": true, "auth token": true, "completion": true,
		"config clear-cache": true, "config get": true, "config list": true, "config set": true,
		"extension create": true, "extension list": true, "licenses": true,
		"skill list": true, "version": true,
	}
	brokerRequestCommands := map[string]bool{
		"auth status": true, "credits": true, "extension install": true,
		"gist create": true, "gist delete": true, "gist edit": true, "gist rename": true, "gist view": true,
		"gpg-key add": true, "gpg-key delete": true,
		"project close": true, "project copy": true, "project create": true, "project delete": true,
		"project edit": true, "project field-create": true, "project field-delete": true, "project field-list": true,
		"project item-add": true, "project item-archive": true, "project item-create": true,
		"project item-delete": true, "project item-edit": true, "project item-list": true,
		"project link": true, "project mark-template": true, "project unlink": true, "project view": true,
		"repo gitignore view": true, "repo license view": true,
		"search commits": true, "search issues": true, "search prs": true, "search repos": true,
		"ssh-key add": true, "ssh-key delete": true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runLivePGHWithOptions(t, liveCommandOptions{directory: isolatedDir, stdin: tt.stdin}, tt.args...)
			wantExitCode := 1
			if successfulCommands[tt.name] {
				wantExitCode = 0
			}
			require.Equal(t, wantExitCode, result.exitCode, result.stderr)
			if brokerRequestCommands[tt.name] {
				require.NotEmpty(t, result.requests, "command did not exercise the Broker or GitHub")
			} else {
				require.Empty(t, result.requests, "command unexpectedly exercised the in-process Broker")
			}
			if wantExitCode != 0 {
				require.NotEmpty(t, result.stderr)
			}
			require.NotContains(t, result.stderr, token)
		})
	}
}
