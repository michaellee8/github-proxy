package pghcmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunnableCommandAuditManifestMatchesLiveCases(t *testing.T) {
	functionNames := map[string]bool{
		"TestLivePGHRepositoryCommandAudit":     true,
		"TestLivePGHGlobalAndLocalCommandAudit": true,
		"TestLivePGHReadOnlyCommandAudit":       true,
	}
	caseNames := []string{
		"api", "repo view", "issue list", "pr list", "label list",
		"release list", "workflow list", "run list",
	}
	for _, filename := range []string{"live_command_audit_test.go", "live_integration_test.go"} {
		parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		require.NoError(t, err)
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !functionNames[function.Name.Name] {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				keyValue, ok := node.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				key, ok := keyValue.Key.(*ast.Ident)
				if !ok || key.Name != "name" {
					return true
				}
				value, ok := keyValue.Value.(*ast.BasicLit)
				if !ok || value.Kind != token.STRING {
					return true
				}
				name, err := strconv.Unquote(value.Value)
				require.NoError(t, err)
				caseNames = append(caseNames, name)
				return true
			})
		}
	}

	seen := make(map[string]bool, len(caseNames))
	for _, name := range caseNames {
		require.False(t, seen[name], "runnable command %q has more than one audit case", name)
		seen[name] = true
	}
	sort.Strings(caseNames)
	require.Equal(t, readCommandAuditManifest(t), caseNames)
}

func readCommandAuditManifest(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("testdata/runnable-command-audit.txt")
	require.NoError(t, err)
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			paths = append(paths, line)
		}
	}
	require.True(t, sort.StringsAreSorted(paths), "command audit manifest must remain sorted")
	return paths
}
